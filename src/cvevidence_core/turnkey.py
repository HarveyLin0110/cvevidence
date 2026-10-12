"""Scope-preserving Turnkey material inventory and evidence-driven requests.

No filesystem layout, embedded string, manifest or recipe proves shipping build.
Company reference samples are never required at runtime or checked into Git.
"""
import csv
import io
import hashlib
import json
import re
from pathlib import PurePosixPath
from .integrity import digest
from .turnkey_container import inspect as inspect_container

FAMILIES = ('auto', '2506', 'e5v40-01', 'unknown')
STATE_LABELS = {'MISSING':'未提供', 'PRESENT_UNBOUND':'已提供，成品關聯待核對',
    'PRESENT_BUT_UNUSABLE':'已提供，但欄位不可用', 'PARSER_UNAVAILABLE':'已保存，讀取能力不足',
    'CONFLICTED':'聲明衝突', 'PRESENT':'已讀取'}


def manifest_rows(text):
    """Buildroot legal-info CSV; the caller preserves host/target scope."""
    try:
        reader = csv.DictReader(io.StringIO(text))
        keys = {k.strip().lower(): k for k in (reader.fieldnames or [])}
        name = keys.get('package'); version = keys.get('version')
        if not name or not version: return []
        return [{'name': r[name], 'version': r[version]} for _,r in zip(range(1000),reader)
                if r.get(name) and r.get(version)]
    except (csv.Error, TypeError): return []


def _scope(path, family):
    lower = path.lower()
    # Hints are deliberately labelled; no inferred same-build identity.
    stage = next((x for x in ('stage2_smb','stage2_minimal','stage1','xstax','bootloaders','standalone') if x in lower), 'UNKNOWN')
    brand = re.search(r'(?:^|/)brand/([^/]+)/', lower)
    return {'family': family, 'brand': brand[1] if brand else 'UNKNOWN', 'stage': stage,
        'purpose': 'bringup' if 'bringup' in lower else 'UNKNOWN',
        'abi': 'uclibc' if 'uclibc' in lower else 'gnu' if '/gnu/' in lower or '-gnu/' in lower else 'UNKNOWN',
        'host_target': 'host' if PurePosixPath(lower).name == 'host-manifest.csv' else 'target',
        'basis': 'PATH_HINT_NOT_BUILD_BINDING', 'shipping_build': 'UNKNOWN'}


def _text_role(path, text):
    name = PurePosixPath(path).name.lower()
    if 'Archive member included to satisfy reference by file (symbol)' in text or ('Linker script and memory map' in text and 'LOAD ' in text):
        return 'application_link_map'
    if manifest_rows(text): return 'host_inventory' if name == 'host-manifest.csv' else 'component_inventory'
    if '"bomFormat"' in text or '"spdxVersion"' in text: return 'sbom'
    if name in ('.config','buildroot.config') and re.search(r'(?m)^(?:BR2_|CONFIG_|# (?:BR2_|CONFIG_))',text): return 'effective_config'
    if 'defconfig' in name: return 'default_config'
    if re.search(r'(?m)^VERSION\s*=\s*\d+\s*$',text) and re.search(r'(?m)^PATCHLEVEL\s*=',text): return 'kernel_source'
    if re.search(r'(?m)^(?:Date|BuildVersion|FirmwareVersion|Revision):',text): return 'build_metadata'
    if name.endswith(('.cksum','.sha256','.sha512')): return 'delivery_checksum'
    if '"fixture_class"' in text and '"SYNTHETIC_TEST_ONLY"' in text:return 'synthetic_test_material'
    if name.endswith(('.mk','.in','.yaml')) or name == 'makefile': return 'recipe'
    if name.endswith(('.log',)) or name.startswith('log.'): return 'build_log'
    if name.endswith(('.c','.h','.cpp','.patch','.diff')): return 'source'
    return 'unknown'


def inventory(context, *, family=None, container_reader=True):
    context.assert_current()
    declared = family or context.manifest.get('turnkey_family', 'auto')
    if declared not in FAMILIES: raise ValueError('Unknown turnkey family')
    materials=[]; total_text=0; truncated=False
    rows=sorted(context.sources.values(),key=lambda r:r['path'])
    for source in rows:
        path=source['path']
        if source['kind']!='file' or path in ('intake-identity.json','manifest.json') or '.rom-inventory/' in path: continue
        if len(materials)>=1000: truncated=True; break
        file=context.root/path
        with file.open('rb') as stream: prefix=stream.read(min(source['size'], 131072))
        detected='UNKNOWN'
        if '/2506/' in '/'+path or 'em17-2506' in path: detected='2506'
        elif '/e5v40-01/' in '/'+path or 'mscc-brsdk-source-2017' in path: detected='e5v40-01'
        scope=_scope(path, detected)
        if detected=='UNKNOWN' and declared in ('2506','e5v40-01'):
            scope.update(family=declared,basis='USER_DECLARED_FAMILY_WITH_PATH_SCOPE_HINTS')
        item={'source_id':source['source_id'],'path':path,'size':source['size'],'sha256':source['sha256'],
              'scope':scope,'declared_family':declared,'material_role':'unknown','observed_format':'UNKNOWN',
              'presence_state':'PRESENT_UNBOUND','observations':[], 'parser':'turnkey-v1',
              'origin':'CURRENT_SNAPSHOT_BYTES','build_binding':'UNKNOWN'}
        item['batch']='CURRENT_SNAPSHOT_WITH_PARENT' if context.manifest.get('parent_context_hash') else 'INITIAL_SNAPSHOT'
        container=inspect_container(file,enabled=container_reader)
        if container['format']=='MFI':
            item.update(observed_format='MFI',material_role='application_update',container=container)
            scope.update(family=container['family'],basis='OBSERVED_HEADER_FAMILY_WITH_PATH_SCOPE_HINTS')
            if scope['purpose']=='bringup':item['material_role']='bringup_update'
            else:scope['purpose']='application'
            item['observations'].append({'kind':'EMBEDDED_DECLARATIONS','value':container['metadata'],
                'locator':container.get('metadata_locator')})
            if container['status'] in ('PARSER_UNAVAILABLE','INVALID_CONTAINER'):item['presence_state']='PARSER_UNAVAILABLE'
            if any(r['version_state']=='PRESENT_BUT_UNUSABLE' for r in container['rootfs']):
                item['observations'].append({'kind':'BSP_VERSION_UNUSABLE','value':'只補缺少的 BSP 身分／hash，不重交已讀到的韌體版本。'})
        elif prefix.startswith(b'\x7fELF'):item.update(material_role='elf',observed_format='ELF')
        elif prefix.startswith(b'hsqs'):item.update(material_role='rootfs',observed_format='SQUASHFS')
        elif b'\0' not in prefix and total_text+len(prefix)<=8*1024*1024:
            total_text+=len(prefix)
            try: text=prefix.decode('utf-8')
            except UnicodeError:text=''
            item['material_role']=_text_role(path,text)
            item['observed_format']='TEXT' if text else 'UNKNOWN'
            item['text_truncated']=source['size']>len(prefix)
            if item['material_role'] in ('component_inventory','host_inventory'):
                item['components']=manifest_rows(text)
            if item['material_role'] in ('effective_config','default_config'):
                item['observations']=[{'kind':'CONFIG_DECLARATION','value':line,'line':n}
                    for n,line in enumerate(text.splitlines(),1)
                    if re.match(r'^(?:BR2_|CONFIG_)(?:PACKAGE_|LINUX_KERNEL|KERNEL|CURL|OPENSSL)|^# (?:BR2_|CONFIG_).* is not set',line)][:80]
            if item['material_role']=='kernel_source':
                version=[re.search(r'(?m)^'+k+r'\s*=\s*(\d+)',text) for k in ('VERSION','PATCHLEVEL','SUBLEVEL')]
                if all(version):item['observations'].append({'kind':'SOURCE_KERNEL_VERSION','value':'.'.join(m[1] for m in version)})
            if item['material_role']=='application_link_map':
                item['observations'].append({'kind':'LINK_MAP_CONTENT_OBSERVED','value':'有 object/library 參照；尚未綁定交付成品。'})
            if item['material_role']=='synthetic_test_material':
                item['production_evidence_eligible']=False
                item['observations'].append({'kind':'NONPRODUCTION_EVIDENCE','value':'合成測試資料，不能綁定真實成品。'})
                try:item['test_record']=json.loads(text)
                except ValueError:pass
            if item['material_role']=='delivery_checksum':
                item['checksum_lines']=text.splitlines()[:30]
            if item['material_role']=='recipe':
                for n,line in enumerate(text.splitlines(),1):
                    if any(x in line for x in ('BSP','RELEASE_VERSION','KERNEL','git clone','-Map','EM17-')):
                        item['observations'].append({'kind':'RECIPE_DECLARATION','value':line[:400],'line':n})
                        if len(item['observations'])>=20:break
        if item['observed_format']=='UNKNOWN' and path.lower().endswith(('.bin','.rom','.img','.mfi')):
            item.update(material_role='opaque_firmware',presence_state='PARSER_UNAVAILABLE')
        if declared not in ('auto','unknown') and scope['family'] not in ('UNKNOWN',declared):
            item['presence_state']='CONFLICTED'
        materials.append(item)
    artifact_roles={'application_update','bringup_update','opaque_firmware','rootfs','elf'}
    known=any(r['material_role']!='unknown' for r in materials)
    state='LIMITED_INVENTORY' if not known or any(r['material_role'] in artifact_roles for r in materials) else 'SOURCE_ONLY'
    if any(r.get('components') for r in materials):state='COMPONENT_METADATA_OBSERVED'
    if any(r.get('container',{}).get('status')=='PARTIAL_METADATA' for r in materials):state='PARTIAL_METADATA'
    relations=[]; sha512_cache={}
    hashes={}
    for r in materials:hashes.setdefault(r['sha256'],[]).append(r)
    for r in materials:
        record=r.pop('test_record',None)
        if isinstance(record,dict):
            links=[];conflict=False
            inputs,outputs=record.get('inputs',[]),record.get('outputs',[])
            if not isinstance(inputs,list) or not isinstance(outputs,list):
                r['presence_state']='PRESENT_BUT_UNUSABLE'
                r['observations'].append({'kind':'INVALID_TEST_RECORD','value':'inputs／outputs 必須是陣列；未建立材料關聯。'})
                inputs,outputs=[],[]
            for ref in (inputs+outputs)[:100]:
                if not isinstance(ref,dict):continue
                target=next((x for x in materials if x['path']==ref.get('packaged_path')),None)
                link_state='MISSING' if target is None else 'MATCHED_TEST_RECORD' if target['sha256']==ref.get('sha256') else 'CONFLICT'
                conflict|=link_state=='CONFLICT'
                links.append({'path':ref.get('packaged_path'),'claimed_sha256':ref.get('sha256'),'state':link_state})
            mismatch=(record.get('test_build_id') and context.manifest['build_id'] not in
                ('未確認',record['test_build_id']))
            r['test_association']={'namespace':'SYNTHETIC_TEST_ONLY','links':links,
                'state':'CONFLICT' if conflict or mismatch else 'MATCHED_TEST_RECORD' if links and all(x['state']=='MATCHED_TEST_RECORD' for x in links) else 'UNKNOWN',
                'hash_conflict':conflict,'scope_conflict':bool(mismatch),'production_evidence_eligible':False}
            if conflict or mismatch:r['presence_state']='CONFLICTED'
        for span in r.get('container',{}).get('spans',[]):
            for member in hashes.get(span['sha256'],[]):
                if member['size']==span['length'] and member['source_id']!=r['source_id']:
                    relations.append({'from_source_id':r['source_id'],'to_source_id':member['source_id'],
                        'state':'CONTAINED_BYTE_IDENTITY','offset':span['offset'],'length':span['length'],
                        'sha256':span['sha256'],'build_binding':'UNKNOWN'})
        for line in r.pop('checksum_lines',[]):
            match=re.fullmatch(r'([a-fA-F0-9]{64}|[a-fA-F0-9]{128})(?:\s+\*?(.+))?',line.strip())
            if not match:continue
            algorithm='sha256' if len(match[1])==64 else 'sha512'
            matched=[]
            for candidate in materials:
                if candidate['source_id']==r['source_id']:continue
                if algorithm=='sha256':h=candidate['sha256']
                else:
                    if candidate['source_id'] not in sha512_cache:
                        with (context.root/candidate['path']).open('rb') as stream:sha512_cache[candidate['source_id']]=hashlib.file_digest(stream,'sha512').hexdigest()
                    h=sha512_cache[candidate['source_id']]
                if h==match[1].lower():matched.append(candidate['source_id'])
            r['observations'].append({'kind':'CONTENT_CHECKSUM','algorithm':algorithm,
                'declared_hash':match[1].lower(),'declared_filename':match[2],
                'filename_basis':'DECLARED_IN_CHECKSUM_CONTENT' if match[2] else 'HASH_ONLY_NO_CONTENT_FILENAME',
                'matched_source_ids':matched,'state':'MATCHED_CONTENT' if matched else 'UNMATCHED',
                'limit':'只證明 bytes 相符，不是來源認證或同次建置。'})
    result={'schema_version':'1.0','context_hash':context.context_hash,'inventory_state':state,
        'declared_family':declared,'materials':materials,'coverage_limited':truncated or total_text>=8*1024*1024,
        'assessment':'NOT_ASSESSED','build_binding':'UNKNOWN','recommendations':[],'relations':relations,
        'note':'材料角色／內容聲明不等於同次建置、出貨、部署或 CVE 結論；不同 scope 保留分開。'}
    result['recommendations']=recommendations(result)
    result['inventory_hash']=digest(result)
    context.assert_current()
    return result


def recommendations(report):
    materials=report['materials']; result=[]
    groups={}
    for item in materials:
        s=item['scope']
        key=tuple(s[k] for k in ('family','brand','stage','purpose','abi','host_target'))
        groups.setdefault(key,[]).append(item)
    for key,items in groups.items():
        scope=items[0]['scope']; family=scope['family'];roles={r['material_role'] for r in items}
        ids=[r['source_id'] for r in items]
        compatible=[r for r in materials if all(scope[k]=='UNKNOWN' or r['scope'][k]=='UNKNOWN' or scope[k]==r['scope'][k]
            for k in ('family','brand','stage','purpose','abi','host_target'))]
        available_roles={r['material_role'] for r in compatible}
        modern=family=='2506'
        def add(code,title,why,paths,done,state='MISSING',owner='建置／BSP 維護者'):
            result.append({'recommendation_id':'REC-'+code,'gap_id':'GAP-'+code,'title':title,
                'presence_state':state,'priority':'NEXT','scope':scope,'why':why,
                'evidence_material_ids':ids[:20],'candidate_paths':paths,'request_owner':owner,
                'completion_condition':done,'build_binding':'UNKNOWN'})
        artifacts=roles & {'application_update','bringup_update','rootfs','elf','opaque_firmware'}
        if any(r['presence_state']=='CONFLICTED' for r in items):
            if any(r.get('test_association',{}).get('hash_conflict') for r in items):
                add('HASH-CONFLICT','核對原件與引用 hash','引用 hash 與實際 bytes 不一致；不修改原件迎合聲明。',[], '取得可解釋衝突的原始資料，保留舊紀錄。','CONFLICTED')
            if any(r.get('test_association',{}).get('scope_conflict') or r['scope']['family'] not in ('UNKNOWN',r['declared_family']) and r['declared_family'] not in ('auto','unknown') for r in items):
                add('CORRECT-SCOPE','確認材料所屬產品／stage','產品家族／建置聲明不一致，不能合成同一 build。',[], '分開案件或確認正確 scope。','CONFLICTED')
        if roles <= {'unknown','synthetic_test_material'}:
            if not any(r.get('test_association') for r in items):
                add('IDENTITY','提供產品／release 聲明','目前材料無可用產品識別。',[], '提供產品名稱、版本及希望查核的成品範圍。',owner='產品／release 維護者')
            continue
        if artifacts and all(not r.get('container',{}).get('metadata') for r in items) and roles <= {'application_update','bringup_update','opaque_firmware'}:
            add('IDENTITY','補可用產品／release 身分','原始成品已保存，但沒有可讀內嵌身分；先補身分聲明。',[], '取得產品／版本的可讀識別，仍不視為已驗建置。')
        if 'kernel_source' in roles or any(r['material_role']=='default_config' and any('LINUX_KERNEL' in o['value'] for o in r['observations']) for r in items):
            if 'effective_config' not in available_roles:
                add('KERNEL-SOURCE-SELECTION','核對 kernel 實際選取來源','來源 Makefile／預設下載配置不能證明這次 build 使用哪份 kernel；保留各自版本。',
                    ['本 target 的 .config','local.mk／source override／該次 CI 來源紀錄'], '有效選取資料能解釋 kernel 的來源版本與該次建置。')
        if not artifacts and not roles <= {'delivery_checksum','host_inventory'}:
            add('DELIVERED-ARTIFACT','後續可補待查成品','目前可先進行來源盤點；若要判斷產品影響，需要實際交付檔案。',
                ['istax/build/obj_<brand>/*.mfi'] if modern else ['IStaX-4.4.0/src/build/obj/*.mfi'], '保存所查成品原始 bytes/hash。')
        if artifacts or 'host_inventory' in roles:
            if not available_roles & {'component_inventory','sbom'}:
                add('COMPONENT-METADATA','補此 target 的元件清單','已存成品／host 清單不能代替此 target 的元件盤點。',
                    ['<BSP>/<ABI>/<target>/release/legal-info/manifest.csv'] if modern else ['output-mips-stage2_smb/legal-info/manifest.csv'],
                    '取得可讀 target manifest 或 SBOM；成品關聯另行核對。')
        if artifacts or roles & {'component_inventory','host_inventory','application_link_map','effective_config','recipe','default_config'}:
            add('BUILD-ASSOCIATION','核對已有材料與成品的建置關聯','材料已提供，尚未有證據證明它們屬於同次建置；不必重傳相同檔案。',
                ['該次 CI 原始建置紀錄、輸入／輸出 hash、組裝紀錄'], '紀錄能對上本 scope 的實際材料與輸出 hash；沒有就保留未知。','PRESENT_UNBOUND')
        for r in items:
            roots=r.get('container',{}).get('rootfs',[])
            if any(x['name']=='rootfs' and x['version_state']=='PRESENT_BUT_UNUSABLE' for x in roots):
                add('BSP-IDENTITY','補不可用的 BSP 身分欄位','內嵌 rootfs VERSION 存在但不是可用版本，不能猜成目前安裝的 SDK。',
                    ['<BSP>/sdk-setup.mk','實際使用 BSP 套件名稱與 SHA256'], '取得可用 BSP 身分／hash，保留原欄位與綁定缺口。','PRESENT_BUT_UNUSABLE');break
        if roles & {'recipe','default_config'} and 'effective_config' not in available_roles:
            add('EFFECTIVE-CONFIG','需要選取條件時補有效配置','配方／defconfig 只是預設，尚不能證明實際選取。',
                ['output/<target>/.config','kernel build/.config'] if modern else ['output-mips-stage<scope>/.config'], '收到本 stage 的有效配置；不擴大到其他成品。')
        if any(r['presence_state']=='PARSER_UNAVAILABLE' or r.get('container',{}).get('format')=='MFI' for r in items) and not available_roles & {'elf','rootfs','component_inventory','sbom'}:
            add('PARSER-ALTERNATIVE','需深入內容時補可讀的分層成品','MFI 目前只讀 metadata/span；未知容器保留原件，並未完成內部元件取證。',
                ['同 stage 的 ELF 或 rootfs（擇一，依待查元件）'], '提供能解除本次內容缺口的最小替代檔案。','PARSER_UNAVAILABLE')
    # One focused next action, remaining scope-specific tasks stay collapsed.
    order={'CORRECT-SCOPE':0,'HASH-CONFLICT':0,'IDENTITY':1,'COMPONENT-METADATA':2,'BSP-IDENTITY':3,'BUILD-ASSOCIATION':4}
    result.sort(key=lambda r:(order.get(r['recommendation_id'][4:],8),str(r['scope'])))
    if result:result[0]['priority']='NOW'
    return result
