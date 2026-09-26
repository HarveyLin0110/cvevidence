"""Component parsing and consented OSV lookup. Symptoms stay local."""
import json,re,urllib.request,hashlib,time
from urllib.parse import unquote
from .sources import text_lines
from .public_cve import _NoRedirect
from .integrity import IntegrityError
ECOSYSTEMS={'pypi':'PyPI','npm':'npm','maven':'Maven','golang':'Go','cargo':'crates.io','nuget':'NuGet','gem':'RubyGems','composer':'Packagist'}


def components(context):
    rows=[];scanned=0
    for source in sorted(context.sources.values(),key=lambda s:(not s['path'].lower().endswith('.json'),s['path'])):
        if source['kind']!='file' or source['size']>2_000_000:continue
        path=source['path'].lower()
        if not path.endswith(('.json','.txt','.manifest','.list','/status','.control')) and path not in ('status','manifest'):continue
        if scanned>=100:break
        scanned+=1
        try:lines=text_lines(context,source['source_id'])
        except IntegrityError:raise
        except (ValueError,UnicodeError):continue
        if not path.endswith('.json'):
            from .package_inventory import parse
            for row in parse(lines):
                rows.append({**row,'purl':'','source_id':source['source_id'],'source_path':source['path'],
                    'source_kind':'PACKAGE_INVENTORY_DECLARATION','query':None,
                    'identity_verified':False})
                if len(rows)>=100:return rows
            continue
        try:data=json.loads('\n'.join(lines))
        except (ValueError,UnicodeError):continue
        if not isinstance(data,dict):continue
        declared=[row for key in ('components','packages') if isinstance(data.get(key),list) for row in data[key]]
        for row in declared:
            if not isinstance(row,dict):continue
            name=row.get('name');version=row.get('version',row.get('versionInfo'));purl=row.get('purl','')
            for ref in row.get('externalRefs',[]) if isinstance(row.get('externalRefs',[]),list) else []:
                if isinstance(ref,dict) and ref.get('referenceType')=='purl':purl=ref.get('referenceLocator','')
            if not isinstance(name,str) or not isinstance(version,str) or not name or not version:continue
            if len(name)>200 or len(version)>100:continue
            query=None
            if isinstance(purl,str) and re.fullmatch(r'pkg:[A-Za-z0-9._/%@+:-]+',purl) and len(purl)<400:
                match=re.fullmatch(r'pkg:([^/]+)/(.+?)(?:@([^@]+))?',purl)
                if match and match[1] in ECOSYSTEMS:
                    pname=unquote(match[2]);ecosystem=ECOSYSTEMS[match[1]]
                    if ecosystem=='Maven':pname=pname.replace('/',':')
                    query={'package':{'name':pname,'ecosystem':ecosystem},'version':version}
            rows.append({'name':name,'version':version,'purl':purl,'source_id':source['source_id'],'source_path':source['path'],
                'source_kind':'SBOM_DECLARATION','query':query})
            if len(rows)>=100:return rows
    return rows


def _query(query,timeout):
    req=urllib.request.Request('https://api.osv.dev/v1/query',data=json.dumps(query).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.build_opener(_NoRedirect()).open(req,timeout=timeout) as response:raw=response.read(2_000_001)
    if len(raw)>2_000_000:raise ValueError('OSV response limit')
    return json.loads(raw),hashlib.sha256(raw).hexdigest()


def discover(context, symptom='', *, consent=False, transport=None):
    inventory=components(context)
    result={'context_hash':context.context_hash,'status':'CONSENT_REQUIRED','candidates':[],
        'components':inventory,'symptom_causation':'NOT_ESTABLISHED','scope':'最多查詢 5 個已識別生態系統的元件；未命中或未涵蓋不代表安全。','queries':[]}
    if consent is not True:return result
    request=transport or _query;deadline=time.monotonic()+20;seen=set();by_cve={}
    terms=set(re.findall(r'[a-z][a-z0-9_]{2,40}',symptom.casefold()))
    for word,english in {'注入':'injection','當機':'crash','逾時':'timeout','超時':'timeout','記憶體':'memory','溢位':'overflow','驗證':'validation','認證':'authentication','阻斷服務':'denial','跨站':'cross-site','路徑穿越':'traversal'}.items():
        if word in symptom:terms.add(english)
    terms.update(word for word in ('cookie','overflow','crash','timeout','tls','memory','authentication') if word in symptom.casefold())
    for component in inventory:
        query=component['query']
        if not query or json.dumps(query,sort_keys=True) in seen:continue
        if len(seen)>=5 or time.monotonic()>=deadline:break
        seen.add(json.dumps(query,sort_keys=True));receipt={'query':query,'source_id':component['source_id']}
        try:
            data,sha=request(query,min(6,deadline-time.monotonic()))
            receipt.update(status='COMPLETED',response_sha256=sha,truncated=bool(data.get('next_page_token')))
            for vuln in data.get('vulns',[])[:100]:
                if not isinstance(vuln,dict):continue
                aliases=[vuln.get('id','')]+vuln.get('aliases',[])
                details=(str(vuln.get('summary',''))+' '+str(vuln.get('details','')))[:16000]
                hits=sorted(w for w in terms if w in details.casefold())
                for cve in aliases:
                    if not isinstance(cve,str) or not re.fullmatch(r'CVE-\d{4}-\d{4,20}',cve):continue
                    item=by_cve.setdefault(cve,{'cve_id':cve,'status':'CANDIDATE_ONLY','assessment':None,
                        'sources':['https://api.osv.dev/v1/query'],'match_basis':[], 'symptom_terms':hits,
                        'symptom_causation':'NOT_ESTABLISHED','summary':str(vuln.get('summary',''))[:600]})
                    item['match_basis'].append({'name':component['name'],'version':component['version'],
                        'source_id':component['source_id'],'source_kind':'SBOM_DECLARATION','public_record_id':vuln.get('id'),
                        'version_hint':'PUBLIC_PACKAGE_VERSION_MATCH_NOT_PRODUCT_VERDICT'})
        except (OSError,ValueError,TypeError,KeyError):receipt.update(status='UNAVAILABLE')
        result['queries'].append(receipt)
    result['candidates']=sorted(by_cve.values(),key=lambda r:(-len(r['symptom_terms']),r['cve_id']))[:20]
    result['status']='COMPLETED' if result['queries'] and all(r['status']=='COMPLETED' for r in result['queries']) else 'PARTIAL' if result['queries'] else 'NO_SUPPORTED_COMPONENT_IDENTITY'
    result['mode']='SIMULATED' if transport else 'LIVE_PUBLIC_DATABASE'
    return result
