"""Small sourced catalog. Candidate discovery never returns an assessment."""
import re
from .buildproof import read_json
CATALOG={
 'CVE-2014-0160':{'component':'openssl','title':'TLS Heartbeat 邊界檢查','sources':['https://openssl-library.org/news/secadv/20140407.txt'],'deep_versions':['1.0.1f'],'profile_status':'REVIEWED_DEMO_PROFILE'},
 'CVE-2022-37434':{'component':'zlib','title':'gzip extra header 複製邊界','sources':['https://github.com/madler/zlib/commit/eff308af425b67093bab25f80f1ae950166bece1','https://github.com/madler/zlib/releases/tag/v1.2.13'],'deep_versions':['1.2.12','1.2.13'],'profile_status':'REVIEWED_DEMO_PROFILE'},
 'CVE-2023-38545':{'component':'curl','title':'SOCKS5 remote hostname 處理','sources':['https://curl.se/docs/CVE-2023-38545.html'],'deep_versions':['8.3.0'],'profile_status':'REVIEWED_DEMO_PROFILE'},
}
def version_hint(cve_id,version):
 if cve_id=='CVE-2014-0160':
  if re.fullmatch(r'1\.0\.1[a-f]?',version) or version=='1.0.2-beta1':return 'MATCHES_ADVISORY'
  if re.fullmatch(r'1\.0\.1[g-z]',version):return 'VERSION_OUTSIDE_REVIEWED_AFFECTED_RANGE'
 elif cve_id=='CVE-2022-37434':
  if version=='1.2.12':return 'MATCHES_ADVISORY'
  if version=='1.2.13':return 'FIX_RELEASE_VERSION'
 elif cve_id=='CVE-2023-38545':
  if re.fullmatch(r'\d+\.\d+\.\d+',version):
   parts=tuple(map(int,version.split('.')))
   return 'MATCHES_ADVISORY' if (7,69,0)<=parts<=(8,3,0) else 'VERSION_OUTSIDE_REVIEWED_AFFECTED_RANGE'
 return 'VERSION_UNRESOLVED'

def discover_candidates(context=None,symptom='',requested_cves=None,scanner_candidates=None):
 requested=list(dict.fromkeys(x.upper().strip() for x in (requested_cves or [])))
 if len(requested)>5 or any(not re.fullmatch(r'CVE-\d{4}-\d{4,}',x) for x in requested):raise ValueError('Provide at most five valid CVE IDs')
 components=[]
 if context:
  sbom=read_json(context,'sbom.cdx.json')
  if sbom:
   row=context.by_path('sbom.cdx.json')[1]
   for component in sbom.get('components',[]):
    if isinstance(component,dict) and isinstance(component.get('name'),str) and isinstance(component.get('version'),str):components.append({'name':component['name'].lower(),'version':component['version'],'source_id':row['source_id'],'source_kind':'SBOM_DECLARATION'})
  record=read_json(context,'build/build-record.json')
  if record:
   row=context.by_path('build/build-record.json')[1]
   for component in record.get('components',[]):
    if isinstance(component,dict) and isinstance(component.get('name'),str) and isinstance(component.get('version'),str):components.append({'name':component['name'].lower(),'version':component['version'],'source_id':row['source_id'],'source_kind':'BUILD_RECORD_DECLARATION'})
 candidates=[]
 for cve_id,item in CATALOG.items():
  matches=[c for c in components if c['name'] in ({'curl','libcurl'} if item['component']=='curl' else {item['component']})]
  if not matches and cve_id not in requested:continue
  candidates.append({'cve_id':cve_id,**item,'match_basis':[{**c,'version_hint':version_hint(cve_id,c['version'])} for c in matches],'requested':cve_id in requested,'assessment':None,'status':'CANDIDATE_ONLY'})
 for cve_id in requested:
  if cve_id not in CATALOG:candidates.append({'cve_id':cve_id,'status':'GENERAL_TRIAGE','profile_status':'AWAITING_RULE_REVIEW','sources':[],'assessment':None})
 scanner_notes=[]
 for item in scanner_candidates or []:
  scanner_notes.append({'input':item,'trust':'UNVERIFIED_SCANNER_CANDIDATE','assessment':None})
 intake_questions=[]
 if not context or not components:
  intake_questions=[{'question':'哪個操作出錯、產品版本為何？','purpose':'定位工程情境，尚不判定 CVE。'},{'question':'請提供相關 log、元件清單或 SBOM，以及成品 hash；能取得 source/build 記錄時一併提供。','purpose':'依實際元件找有來源的候選，而不是從症狀猜漏洞。'}]
 return {'symptom':symptom,'candidates':candidates,'scanner_candidates':scanner_notes,'intake_questions':intake_questions,'scope':'Three reviewed engineering profiles; other requested CVEs enter general investigation. Automatic component discovery is still limited to this catalog; no match does not mean no vulnerabilities.','symptom_causation':'NOT_ESTABLISHED'}
