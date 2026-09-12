"""PC3 checks supplied observations, never executes uploaded programs.

Receipt/hash checks establish consistency, not who collected the observation.
Protocol-specific checks are deliberately limited to today's reviewed profiles.
"""
import datetime
import json
import math
import re
import struct
import zlib
from pathlib import PurePosixPath
from .integrity import digest

RECEIPT = 'runtime/observation.json'
SUBJECTS = {'rom': 'product/device-management', 'cmake': 'product/update-reader',
            'curl': 'install/bin/curl'}
LIBRARIES = {'rom': ['sdk/lib/libssl.so.1.0.0', 'sdk/lib/libcrypto.so.1.0.0'],
             'cmake': [], 'curl': ['install/lib/libcurl.so.4.8.0']}


def _json(pair):
    if pair[1]['kind'] != 'file' or pair[1]['size'] > 1_000_000:
        raise ValueError('觀測檔必須為有界的一般檔案')
    return json.loads(pair[0].read_text(encoding='utf-8'))


def _query(b, cve, target, question):
    identity = {'cve_id': cve, 'build_id': b.context.manifest['build_id'],
                'artifact': b.context.manifest['primary_artifact'], 'target': target}
    row = {'query_id': 'DQ-' + digest(identity)[:20], 'origin': 'RULE_GAP',
           'question': question, 'reason': '核對 PC3 的同成品運作材料；不以原碼或文字聲明替代。',
           'target_condition_id': 'runtime_observation', 'required_files': [target],
           'status': 'WAITING_USER_INPUT', 'evidence_ids': [],
           'context_hash': b.context.context_hash}
    b.followup_queries.append(row)
    return row


def collect_operational(b, cve):
    c = b.context
    summary = {'status': 'MISSING', 'evidence_basis': 'NOT_OBSERVED',
               'description': '尚無同成品的運作證據；PC2 靜態路徑不等於 PC3 實際觀測。',
               'provenance_verified': False}
    b.runtime_observation = summary
    facts = {x['fact_key']: x['value'] for x in b.evidence}
    # A verified implementation block can settle applicability without a runtime test.
    guards = all(facts.get(k) is True for k in ('build_identity', 'library_binding', 'product_binding', 'scope_complete'))
    if facts.get('vulnerable_implementation') is False and guards and not any(q['conflicts'] for q in b.queries.values()):
        summary.update(status='NOT_REQUIRED', description='PC2 已有有效實作阻斷；本次結論不要求追加運作測試，PC3 未觀測。')
        b.emit('Q5_PATH', 'runtime_observation', None, reason=summary['description'])
        return
    receipt_query = _query(b, cve, RECEIPT, '請提供本次設備／成品的運作收據，指出原始輸出與配置在哪裡。')
    receipt_pair = c.by_path(RECEIPT)
    ids = []
    excerpts = []
    active_query = receipt_query
    material_queries = []
    behavior_started = False
    try:
        if not receipt_pair:
            b.gap('Q5_PATH', '請補 runtime/observation.json：同 build／成品、收集時間、執行命令及原始觀測檔案。')
            return
        ids.append(receipt_pair[1]['source_id'])
        receipt = _json(receipt_pair)
        if not isinstance(receipt, dict) or receipt.get('schema_version') != '1.0':
            raise ValueError('不支援的運作收據格式')
        for key in ('product_id', 'release_id', 'build_id', 'primary_artifact', 'format'):
            if receipt.get(key) != c.manifest[key]:
                raise ValueError('運作收據與本次成品身分不符：' + key)
        observed = datetime.datetime.fromisoformat(receipt['observed_at'])
        if observed.tzinfo is None:
            raise ValueError('運作時間需有時區')
        basis = receipt.get('evidence_basis')
        if basis not in ('CONTROLLED_LOCAL_OBSERVATION', 'USER_SUPPLIED_OBSERVATION'):
            raise ValueError('需標示觀測環境，不能以實驗環境冒充實機部署')
        subject = c.by_path(SUBJECTS[c.manifest['format']])
        if not subject or receipt.get('subject') != {'path': SUBJECTS[c.manifest['format']], 'sha256': subject[1]['sha256']}:
            raise ValueError('運作程式未綁定本次成品')
        libs = [{'path': path, 'sha256': c.by_path(path)[1]['sha256']} for path in LIBRARIES[c.manifest['format']] if c.by_path(path)]
        if len(libs) != len(LIBRARIES[c.manifest['format']]) or receipt.get('libraries') != libs:
            raise ValueError('運作 library 未綁定本次交付')
        ids += [subject[1]['source_id'], *[c.by_path(x['path'])[1]['source_id'] for x in libs]]
        command = receipt.get('command')
        if not isinstance(command, dict) or type(command.get('exit_code')) is not int or command['exit_code'] != 0:
            raise ValueError('缺少成功的正常操作命令收據；失敗不能當成安全')
        if not isinstance(command.get('argv'), list) or not command['argv'] or any(not isinstance(x, str) or len(x) > 1000 for x in command['argv']):
            raise ValueError('命令收據格式無效')
        receipt_query['status'] = 'VERIFIED'
        receipt_query['evidence_ids'] = [b.emit('Q5_PATH', 'runtime_receipt_binding', True, ids,
            '運作收據的成品、library 與時間欄位已核對；尚不代表其原始觀測足夠或來源已認證。')['evidence_id']]
        summary.update(status='AWAITING_EVIDENCE', evidence_basis=basis,
                       description='已核對運作收據，接著驗證原始輸出與實際配置。')
        needed = ['capture'] + (['configuration'] if c.manifest['format'] == 'curl' else ['sample'] if c.manifest['format'] == 'cmake' else [])
        materials = {}
        missing = False
        for name in needed:
            ref = receipt.get(name)
            if not isinstance(ref, dict) or not isinstance(ref.get('path'), str):
                raise ValueError('收據缺少必要材料定位：' + name)
            path = ref['path']
            if not path.startswith('runtime/') or '..' in PurePosixPath(path).parts or not re.fullmatch(r'[a-f0-9]{64}', ref.get('sha256', '')):
                raise ValueError('觀測來源定位或 hash 無效')
            active_query = _query(b, cve, path, '請核對新收到的運作收據所引用的 ' + path + '，確認原始內容是否支持必要條件。')
            material_queries.append(active_query)
            pair = c.by_path(path)
            if not pair:
                missing = True
                b.gap('Q5_PATH', '運作收據已收到，仍缺原始材料：' + path)
                continue
            if pair[1]['kind'] != 'file' or pair[1]['size'] > 1_000_000 or pair[1]['sha256'] != ref['sha256']:
                raise ValueError('運作原始材料 hash／大小不符：' + path)
            materials[name] = pair[0].read_bytes()
            ids.append(pair[1]['source_id'])
            active_query['status'] = 'WAITING_VERIFICATION'
            active_query['evidence_ids'] = [b.emit('Q5_PATH', 'runtime_material_' + name, True, [pair[1]['source_id']],
                '收據引用與原始材料 bytes 一致；內容意義由後續格式規則核對。')['evidence_id']]
            excerpt = b.excerpt(path, '') if name != 'sample' else None
            if excerpt: excerpts.append(excerpt)
        if missing:
            return
        behavior_started = True
        _validate_behavior(c.manifest['format'], materials, command,
                           component_version=(facts.get('component') or {}).get('version'),
                           material_paths={name: receipt[name]['path'] for name in needed})
        for query in material_queries:
            query['status'] = 'VERIFIED'
        summary.update(status='VERIFIED', description='同成品正常運作紀錄與必要配置已由對應格式規則核對；不是漏洞重現或實體設備認證。')
    except (ValueError, KeyError, TypeError, UnicodeError, OverflowError, IndexError) as error:
        summary.update(status='REJECTED', description='運作證據不一致或不足，保留未知並要求覆核。')
        active_query['status'] = 'REJECTED'
        if behavior_started:
            # These records must agree as a set. Do not bless a bad capture while
            # blaming whichever unrelated file happened to be visited last.
            for query in b.followup_queries:
                query['status'] = 'REJECTED'
                query['reason'] = '收據、命令與原始材料的交叉驗證未通過；hash 一致仍不足以證明內容，請覆核此資料組合。'
        b.conflict('Q5_PATH', 'PC3 運作證據需覆核：' + str(error)[:240])
    finally:
        b.emit('Q5_PATH', 'runtime_observation', True if summary['status'] == 'VERIFIED' else None,
               ids, summary['description'], excerpts)


def _validate_behavior(family, materials, command, component_version=None, material_paths=None):
    material_paths = material_paths or {'configuration': 'runtime/download.conf', 'sample': 'runtime/normal.gz'}
    if family == 'rom':
        text = materials['capture'].decode('utf-8')
        markers = ('transport=TCP bind=127.0.0.1', 'tls_client_roundtrip=ok protocol=TLSv1.2 openssl=OpenSSL 1.0.1f',
                   'tls_server_receive=ok', 'normal_tcp_tls=ok no_attack_payload=true')
        if not all(x in text for x in markers) or command['argv'] != ['python3', 'tcp_smoke.py', 'unpacked/bin/device-management']:
            raise ValueError('未支持正常 TLS 入口運作；單純原碼或截圖不構成此格式的觀測')
    elif family == 'cmake':
        text = materials['capture'].decode('utf-8').strip()
        match = re.fullmatch(r'update_read=ok zlib=(1\.2\.1[23]) extra_len=(\d+) extra_capacity=32 chunk_bytes=8 output_bytes=(\d+)', text)
        sample = materials['sample']
        if not match or len(sample) < 12 or sample[:4] != b'\x1f\x8b\x08\x04':
            raise ValueError('缺少正常 gzip extra/chunk 原始輸出與樣本')
        if component_version and match[1] != component_version:
            raise ValueError('運作輸出的 zlib 版本與成品實作不符')
        length = struct.unpack('<H', sample[10:12])[0]
        if not 0 < length <= 32 or length != int(match[2]) or len(sample) < 12 + length or int(match[3]) <= 0:
            raise ValueError('gzip 樣本與正常操作輸出不一致')
        try:
            decoder = zlib.decompressobj(wbits=31)
            output = decoder.decompress(sample, 1_000_001)
            if (len(output) > 1_000_000 or not decoder.eof or decoder.unused_data
                    or decoder.unconsumed_tail or len(output) != int(match[3])):
                raise ValueError('gzip 不完整、超過正常樣本上限或輸出長度不符')
        except zlib.error as error:
            raise ValueError('gzip 壓縮資料或 CRC／trailer 未通過完整性驗證') from error
        if command['argv'] != [SUBJECTS[family], material_paths['sample']]:
            raise ValueError('運作命令未指向此成品及樣本')
    else:
        trace = json.loads(materials['capture'])
        config = materials['configuration'].decode('utf-8')
        if not isinstance(trace, dict): raise ValueError('SOCKS5 trace 格式無效')
        greeting = bytes.fromhex(trace['greeting_hex'])
        request = bytes.fromhex(trace['connect_hex'])
        delay = trace['greeting_delay_seconds']
        if (greeting != b'\x05\x01\x00' or len(request) < 7 or request[:4] != b'\x05\x01\x00\x03'
                or len(request) != 7 + request[4] or not request[4]
                or type(delay) not in (int, float) or not math.isfinite(delay) or not 0 < delay <= 10):
            raise ValueError('未觀測到正常 SOCKS5 remote-DNS 與延遲交互')
        values = {}
        for line in config.splitlines():
            if '=' not in line: continue
            key,value=line.split('=',1);key=key.strip()
            if key in values: raise ValueError('重複的配置項目需覆核')
            values[key]=value.strip().strip('"')
        if not re.fullmatch(r'127\.0\.0\.1:\d+', values.get('socks5-hostname', '').strip()) or values.get('limit-rate', '').strip() != '16384' or values.get('noproxy', '').strip() != '':
            raise ValueError('本 profile 的 SOCKS5／buffer 配置未獲支持')
        if len(command['argv']) != 5 or command['argv'][:4] != ['install/bin/curl', '--config', material_paths['configuration'], '--url']:
            raise ValueError('命令未綁定已觀測配置')
        from urllib.parse import urlsplit
        target = urlsplit(command['argv'][command['argv'].index('--url') + 1])
        if request[5:-2].decode('ascii') != target.hostname or int.from_bytes(request[-2:], 'big') != target.port or trace.get('stdout') != 'fresh update payload\n':
            raise ValueError('SOCKS5 原始交互與正常下載命令／輸出不一致')
