"""Five deterministic investigations of the current delivered snapshot only."""
from __future__ import annotations
import hashlib,json,pathlib,re,subprocess
from importlib.resources import files
from .buildproof import BuildProof,read_json
from .catalog import CATALOG
from .evidence import EvidenceBuilder
from .integrity import IntegrityError,UnsupportedError

REVIEW=json.loads(files('cvevidence_core').joinpath('reviewed_sources.json').read_text())
PROFILE_VERSION=REVIEW['profile_revision']+'-runtime-v2'
FORMAT={'CVE-2014-0160':'rom','CVE-2022-37434':'cmake','CVE-2023-38545':'curl'}

def reviewed(context,name,exclude=()):
    ids=[];missing=[]
    for path,expected in REVIEW['sources'][name].items():
        if path in exclude:continue
        pair=context.by_path(path)
        if not pair:missing.append(path)
        elif pair[1]['sha256']!=expected:missing.append('需重新審查已變更的原始碼：'+path)
        else:ids.append(pair[1]['source_id'])
    return not missing,ids,missing

def _proof(builder,query,key,proof,reason):
    for item in proof.get('missing',[]):builder.gap(query,item)
    for item in proof.get('conflicts',[]):builder.conflict(query,item)
    return builder.emit(query,key,True if proof['valid'] else None,proof['source_ids'],reason)

def _review(builder,query,name,exclude=()):
    good,ids,missing=reviewed(builder.context,name,exclude)
    for item in missing:builder.gap(query,item)
    return good,ids

def _excerpts(builder,pairs):
    return [x for path,needle in pairs if (x:=builder.excerpt(path,needle))]

def rom_scope(context):
    """Independently inspect the image; never run its programs or trust unpack logs."""
    image=context.by_path('images/device.rom');ids=[];missing=[];conflicts=[]
    if not image:return {'valid':False,'source_ids':[],'missing':['images/device.rom'],'conflicts':[]}
    ids.append(image[1]['source_id'])
    proc=subprocess.run(['/usr/bin/unsquashfs','-ll',str(image[0])],capture_output=True,text=True,timeout=10)
    if proc.returncode:raise IntegrityError('SquashFS inventory cannot be inspected')
    inventory={}
    for line in proc.stdout.splitlines():
        if ' squashfs-root/' not in line:continue
        mode=line[0];tail=line.split(' squashfs-root/',1)[1]
        if mode!='d':inventory[tail.split(' -> ',1)[0]]=(mode,tail.split(' -> ',1)[1] if ' -> ' in tail else None)
    expected={'bin/device-management':'product/device-management','etc/device.conf':'unpacked/etc/device.conf',
              'lib/libssl.so.1.0.0':'sdk/lib/libssl.so.1.0.0','lib/libcrypto.so.1.0.0':'sdk/lib/libcrypto.so.1.0.0','lib/libz.so.1.2.13':'sdk/lib/libz.so.1.2.13'}
    links={'lib/libssl.so':'libssl.so.1.0.0','lib/libcrypto.so':'libcrypto.so.1.0.0','lib/libz.so':'libz.so.1.2.13','lib/libz.so.1':'libz.so.1.2.13'}
    if set(inventory)!=set(expected)|set(links):missing.append('ROM 包含未涵蓋的檔案或缺少預期檔案；無法確認全成品範圍')
    for path,target in links.items():
        if inventory.get(path)!=('l',target):conflicts.append('ROM library link differs: '+path)
    for path,witness in expected.items():
        pair=context.by_path(witness)
        if not pair:missing.append(witness);continue
        if inventory.get(path)!=('-',None):conflicts.append('ROM regular-file inventory differs: '+path);continue
        # The declared demo profile permits these five bounded files only.
        if pair[1]['size']>10_000_000:raise IntegrityError('ROM member exceeds profile size limit')
        result=subprocess.run(['/usr/bin/unsquashfs','-cat',str(image[0]),path],capture_output=True,timeout=10)
        if result.returncode or hashlib.sha256(result.stdout).hexdigest()!=pair[1]['sha256']:conflicts.append('ROM bytes differ: '+path)
        ids.append(pair[1]['source_id'])
    return {'valid':not missing and not conflicts,'source_ids':ids,'missing':missing,'conflicts':conflicts}

def runtime_scope(context,prefix,expected):
    """An extra executable/shared object in the delivery prevents a whole-scope block."""
    observed=set();ids=[]
    for row in context.sources.values():
        if row['kind']!='file' or not row['path'].startswith(prefix):continue
        p,_=context.source(row['source_id'])
        with p.open('rb') as f:magic=f.read(4)
        if magic==b'\x7fELF':observed.add(row['path']);ids.append(row['source_id'])
    return {'valid':observed==set(expected),'source_ids':ids,'conflicts':[],
            'missing':[] if observed==set(expected) else ['交付範圍有未涵蓋或缺少的 ELF 成品：'+str(sorted(observed^set(expected)))]}

def _rom(b,proof):
    c=b.context
    known,sids=_review(b,'Q1_COMPONENT','openssl-1.0.1f')
    b.emit('Q1_COMPONENT','component',{'name':'openssl','version':'1.0.1f','confirmed':known},sids,'版本標頭與已審查 upstream 程式一致；尚須核對實際連結。')
    library=proof.shared_proof('sdk/lib/libssl.so.1.0.0','source/openssl/libssl.a')
    product=proof.product_proof('product/device-management','source/device.c','sdk/lib/libssl.so.1.0.0','libssl.so.1.0.0')
    _proof(b,'Q4_BINDING','library_binding',library,'SDK libssl → 實際 shared link → archive 每個 object → 同次 source/header。')
    _proof(b,'Q4_BINDING','product_binding',product,'產品 source → object → executable；DT_NEEDED 與實際 linker map 指向該 libssl。')
    _proof(b,'Q4_BINDING','scope_complete',rom_scope(c),'直接解析 ROM 檔案清單並比對其中成品與 library bytes；不執行 ROM。')
    states=[];witnesses=list(sids);excerpts=[]
    for name in ['t1_lib','s3_pkt']:
        records=[r for r in library.get('records',[]) if any(i['path']=='source/openssl/ssl/'+name+'.c' for i in r['inputs'])]
        pp=c.by_path('build/'+name+'.i')
        if not records or not pp:b.gap('Q3_IMPLEMENTATION','同 build 的 '+name+' compile/preprocess 證據');continue
        r=records[0];disabled='-DOPENSSL_NO_HEARTBEATS' in r['argv']
        if any(a.startswith('-UOPENSSL_NO_HEARTBEATS') or a.startswith('-DOPENSSL_NO_HEARTBEATS=') for a in r['argv']):continue
        precords=proof.output_records(path='build/'+name+'.i',sha256=pp[1]['sha256'])
        if not precords or ('-DOPENSSL_NO_HEARTBEATS' in precords[0]['argv'])!=disabled:continue
        check=proof.check_record(precords[0])
        text=pp[0].read_text()
        pattern=r'int\s+tls1_process_heartbeat\s*\(SSL \*s\)\s*\{' if name=='t1_lib' else r'tls1_process_heartbeat\(s\)'
        present=bool(re.search(pattern,text))
        if not check['valid'] or present==disabled:b.conflict('Q3_IMPLEMENTATION','旗標與預處理實作不一致：'+name);continue
        states.append(present);witnesses += [r['source_id'],pp[1]['source_id'],*check['source_ids']]
        excerpt=b.excerpt('build/'+name+'.i','tls1_process_heartbeat')
        if excerpt:excerpts.append(excerpt)
    state=states[0] if known and len(states)==2 and len(set(states))==1 else None
    if len(set(states))>1:b.conflict('Q3_IMPLEMENTATION','Heartbeat 實作與 dispatch 的編譯狀態不一致')
    b.emit('Q3_IMPLEMENTATION','vulnerable_implementation',state,witnesses,'核對 heartbeat 函式、TLS record dispatch 及兩者實際編譯旗標；off 必須兩處一起排除。',excerpts)
    entry,eids=_review(b,'Q4_BINDING','reviewed-demo-entry')
    b.emit('Q4_BINDING','entry_reachable',True if entry and known and product['valid'] else None,[*eids,*sids],
           'TCP accept → SSL_set_fd/SSL_accept → SSL_read → method ssl3_read → ssl3_read_bytes → heartbeat dispatch；表示交付程式的可達能力，未判定外部部署暴露。',
           _excerpts(b,[('source/device.c','SSL_read(connection'),('source/openssl/ssl/ssl_lib.c','s->method->ssl_read'),('source/openssl/ssl/s3_lib.c','s->method->ssl_read_bytes'),('source/openssl/ssl/s3_pkt.c','tls1_process_heartbeat(s)')]))
    b.emit('Q4_BINDING','trigger_prerequisites',True if entry and known else None,[*eids,*sids],'已審查 TLS1.2 method dispatch 可處理 heartbeat record；正常連線不等於已重現漏洞。')

def _cmake(b,proof):
    c=b.context;version=None;sids=[]
    for v in ['1.2.12','1.2.13']:
        good,ids,_=reviewed(c,'zlib-'+v)
        if good:version=v;sids=ids;break
    if not version:b.gap('Q1_COMPONENT','需要已審查的 zlib 標頭及 inflate.c；改版需重新審查')
    b.emit('Q1_COMPONENT','component',{'name':'zlib','version':version,'confirmed':bool(version)},sids,'用實際版本標頭與 inflate.c 核對，不能只用 SBOM 判定。')
    library=proof.archive_proof('build/cmake/zlib/libz.a')
    product=proof.product_proof('product/update-reader','source/update_reader.c','build/cmake/zlib/libz.a')
    _proof(b,'Q4_BINDING','library_binding',library,'核對靜態 archive 每個 member 的 object hash 與編譯 source/header。')
    _proof(b,'Q4_BINDING','product_binding',product,'產品 object 與 linker 實際輸入的 libz.a hash 一致。')
    _proof(b,'Q4_BINDING','scope_complete',runtime_scope(c,'product/',['product/update-reader']),'目前交付 product 目錄的 ELF 範圍。')
    b.emit('Q3_IMPLEMENTATION','vulnerable_implementation',None if not version else version=='1.2.12',sids,'核對 EXTRA copy 的 len/extra_max 條件；1.2.13 包含上游修正。',_excerpts(b,[('source/zlib/inflate.c','case EXTRA:')]))
    entry,eids=_review(b,'Q4_BINDING','reviewed-gzip-entry')
    path=True if entry and product['valid'] else None
    b.emit('Q4_BINDING','entry_reachable',path,eids,'命令列提供任意 gzip 檔案，經 inflateInit2(31)、inflateGetHeader 進入 gzip 解碼。',_excerpts(b,[('source/update_reader.c','inflateGetHeader')]))
    b.emit('Q4_BINDING','trigger_prerequisites',path,eids,'gz_header.extra 容量 32 bytes、每次輸入 8 bytes；程式未拒絕超長 extra，可跨次進入 EXTRA 複製。正常截短檔錯誤不是漏洞重現。',_excerpts(b,[('source/update_reader.c','unsigned char extra')]))

def _curl(b,proof):
    c=b.context;socks='source/curl/lib/socks.c'
    known,sids=_review(b,'Q1_COMPONENT','curl-8.3.0',exclude=[socks])
    old,oldids,_=reviewed(c,'curl-8.3.0',exclude=[p for p in REVIEW['sources']['curl-8.3.0'] if p!=socks])
    fixed,fixids,_=reviewed(c,'curl-8.3.0-patched')
    b.emit('Q1_COMPONENT','component',{'name':'curl','version':'8.3.0','confirmed':known},sids,'標頭和呼叫路徑原始碼已核對；同版號可有不同修補狀態。')
    library=proof.direct_shared_proof('install/lib/libcurl.so.4.8.0')
    product=proof.product_proof('install/bin/curl','source/curl/src/tool_main.c','install/lib/libcurl.so.4.8.0','libcurl.so.4')
    # Cover every linked tool object, including tool_operate/getparam, not just main.
    for link in product.get('records',[])[1:]:
        for item in link.get('inputs',[]):
            if not item['path'].endswith('.o') or item.get('external'):continue
            records=proof.output_records(path=item['path'],sha256=item['sha256'])
            if not records:product['missing'].append('curl tool object compiler record: '+item['path']);continue
            check=proof.check_record(records[0]);product['source_ids']+=check['source_ids'];product['missing']+=check['missing'];product['conflicts']+=check['conflicts']
            if not records[0].get('dependency_capture'):product['missing'].append('curl tool object header capture: '+item['path'])
    product['valid']=product['valid'] and not product['missing'] and not product['conflicts']
    _proof(b,'Q4_BINDING','library_binding',library,'實際 shared library 連結的每個 object 與 source/header hash 核對。')
    _proof(b,'Q4_BINDING','product_binding',product,'curl 執行檔及所有 CLI object 綁定；含參數解析與 buffer 設定程式。')
    _proof(b,'Q4_BINDING','scope_complete',runtime_scope(c,'install/',['install/bin/curl','install/lib/libcurl.so.4.8.0']),'交付 install 中全部 ELF；TLS 未建入，本 profile 僅討論 curl SOCKS5。')
    if not(old or fixed):b.gap('Q3_IMPLEMENTATION','socks.c 未符合已審查版本或官方修補，需重新審查')
    b.emit('Q3_IMPLEMENTATION','vulnerable_implementation',True if old else False if fixed else None,[*oldids,*fixids],
           '檢查 SOCKS5 async state 的本地 DNS 旗標與 hostname > 255 路徑；修補版會直接拒絕過長 hostname。',_excerpts(b,[(socks,'hostname_len > 255')]))
    entry,eids=_review(b,'Q4_BINDING','reviewed-curl-entry')
    ready=entry and known and product['valid']
    b.emit('Q4_BINDING','entry_reachable',True if ready else None,[*eids,*sids],
           '靜態查核：已審查 launcher 接受外部 URL、載入交付 libcurl；host parser 未強制 DNS 255-byte 上限。尚未觀測部署配置。',
           _excerpts(b,[('install/download-update.sh','--url'),('source/curl/lib/urlapi.c','static CURLUcode hostname_check')]))
    b.emit('Q4_BINDING','trigger_prerequisites',True if ready else None,[*eids,*sids],
           '靜態查核：SOCKS5 async state、hostname 與 buffer 設定分支存在；是否真的使用 remote DNS、buffer 設定及延遲交互另由 PC3 查核。',
           _excerpts(b,[('source/curl/src/tool_operate.c','config->recvpersecond < BUFFER_SIZE'),(socks,'case CONNECT_SOCKS_READ:')]))

def collect_evidence(context,cve_id):
    context.assert_current()
    if cve_id not in CATALOG:
        from .general_triage import collect
        return collect(context,cve_id)
    b=EvidenceBuilder(context);proof=BuildProof(context)
    for item in proof.missing:b.gap('Q2_BUILD',item)
    for item in proof.conflicts:b.conflict('Q2_BUILD',item)
    record=context.by_path('build/build-record.json')
    b.emit('Q2_BUILD','build_identity',True if proof.record and not proof.conflicts else None,[record[1]['source_id']] if record else [],'比對 build/product/release/primary artifact；此為交付紀錄內部一致性，不是供應商簽章。')
    if context.manifest['format']!=FORMAT[cve_id]:
        for q in b.queries:b.gap(q,'此 CVE 尚未支援該交付格式的深入分析；不能推定安全')
    else:
        {'rom':_rom,'cmake':_cmake,'curl':_curl}[context.manifest['format']](b,proof)
        # Report actual captured compiler configuration; no inference from names.
        source={'rom':'source/device.c','cmake':'source/update_reader.c','curl':'source/curl/src/tool_operate.c'}[context.manifest['format']]
        config_records=proof.source_records(source)
        config_ids=[];config_values=[]
        for rec in config_records:
            check=proof.check_record(rec)
            if check['valid']:
                config_ids+=check['source_ids']
                config_values.append({'record':rec['record_path'],'argv':rec['argv']})
        if not config_values:b.gap('Q2_BUILD','缺少同成品主要入口的實際編譯／功能設定紀錄')
        b.emit('Q2_BUILD','feature_configuration',config_values or None,config_ids,
               '核對實際編譯命令及來源／產物 hash；功能是否排除另與 Q3 的實作及 Q4 綁定交叉核對。')
        from .operational import collect_operational
        collect_operational(b,cve_id)
    context.assert_current()
    return b.result(cve_id,PROFILE_VERSION)
