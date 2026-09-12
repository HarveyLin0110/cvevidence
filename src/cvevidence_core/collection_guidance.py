"""Parser collection instructions, never observations or assessment evidence."""
import json
from copy import deepcopy
from pathlib import PurePosixPath

from .operational import RECEIPT, SUBJECTS, LIBRARIES


PROFILES = {
    'rom': ('CVE-2014-0160', [
        ('capture', 'runtime/tls.log', '正常 TLS 運作原始日誌',
         '由測試負責人匯出同一成品的既有 TCP／TLS 正常往返紀錄，保留原始輸出。',
         '核對 TLS 入口、版本與正常往返；一般截圖或口述不能替代原始紀錄。')]),
    'cmake': ('CVE-2022-37434', [
        ('capture', 'runtime/normal.log', '正常更新匯入的原始輸出',
         '由測試或維運負責人匯出同一成品一次既有正常匯入的完整 stdout／stderr。',
         '核對成品、zlib 版本、extra 長度、分段讀取及輸出長度。'),
        ('sample', 'runtime/normal.gz', '該次正常匯入使用的 gzip 原檔',
         '向同次測試的負責人取得原始 gzip 樣本，與上項日誌配對；不要重新壓縮。',
         '核對合法的小型 extra 欄位、完整 CRC／trailer 與實際解壓長度，不能只提供檔名。')]),
    'curl': ('CVE-2023-38545', [
        ('capture', 'runtime/socks5-wire.json', '正常 SOCKS5 交互原始紀錄',
         '由網路或測試負責人匯出既有正常下載的 greeting／connect bytes、延遲及原始輸出。',
         '目前讀取 greeting_hex、connect_hex、greeting_delay_seconds、stdout；一般 PCAP 仍需人工轉交受支援格式。'),
        ('configuration', 'runtime/download.conf', '該次下載實際使用的配置',
         '由部署或測試負責人匯出該次下載實際生效的配置，和命令、交互紀錄一起核對。',
         '核對代理解析方式與配置；不能拿另一份預設設定代替當次生效內容。')]),
}


def collection_guide(context, verified, assessment):
    """Called after investigation validates the context, verifier and assessment."""
    family = context.manifest['format']
    profile = PROFILES.get(family)
    states = {x['condition_id']: x['state'] for x in assessment['conditions']}
    if (not profile or profile[0] != verified.cve_id
            or states.get('runtime_observation') != 'UNKNOWN'
            or states.get('vulnerable_implementation') == 'BLOCKED'):
        return None
    definitions = [('receipt', RECEIPT, '同成品運作收據',
                    '由部署或測試負責人整理既有運作紀錄的時間、環境、成品與命令，並引用下列原始檔及 SHA-256。',
                    '把觀測與這一份成品綁定；只有收據、缺原始材料時仍不能完成驗證。'), *profile[1]]
    # Only use receipt references after its identity was checked by the parser.
    receipt = {}
    if any(r['fact_key'] == 'runtime_receipt_binding' and r['value'] is True for r in verified.records):
        pair = context.by_path(RECEIPT)
        if pair and pair[1]['kind'] == 'file' and pair[1]['size'] <= 1_000_000:
            try:
                candidate = json.loads(pair[0].read_text())
                if isinstance(candidate, dict): receipt = candidate
            except (ValueError, OSError, UnicodeError):
                pass
    items = []
    for role, default_path, title, how, purpose in definitions:
        reference = receipt.get(role)
        candidate = reference.get('path') if isinstance(reference, dict) else None
        path = candidate if (isinstance(candidate, str) and len(candidate) <= 1000
                             and candidate.startswith('runtime/')
                             and '..' not in PurePosixPath(candidate).parts) else default_path
        pair = context.by_path(path)
        items.append({'role': role, 'title': title, 'path': path, 'how': how, 'purpose': purpose,
                      'present': bool(pair), 'source_id': pair[1]['source_id'] if pair else None})
    return {'schema_version': '1.0', 'origin': 'CORE_PARSER_CONTRACT',
            'context_hash': context.context_hash, 'cve_id': verified.cve_id,
            'assessment_id': assessment['assessment_id'], 'items': items,
            'notice': '這是核心收件指引，不是已完成的觀測或 AI 取證。只檢查列出的路徑；其他位置的材料需先查找，已收件不代表內容已通過。',
            'details': {
                'scope': {k: deepcopy(context.manifest[k]) for k in ('product_id', 'release_id', 'build_id', 'format', 'primary_artifact')},
                'receipt_path': RECEIPT,
                'receipt_fields': ['schema_version=1.0', 'product_id', 'release_id', 'build_id', 'format',
                                   'primary_artifact（path、sha256）', 'observed_at（實際時間，含時區）',
                                   'evidence_basis（依真實環境填 CONTROLLED_LOCAL_OBSERVATION 或 USER_SUPPLIED_OBSERVATION）',
                                   'subject（path、sha256）', 'libraries（path、sha256 清單）',
                                   'command（實際 argv 與 exit_code；失敗不能填成成功）',
                                   *[role + '（原始檔 path、sha256）' for role, *_ in profile[1]]],
                'subject_path': SUBJECTS[family], 'library_paths': list(LIBRARIES[family]),
                'format_note': '原始材料須在 runtime/；可用不同檔名，但收據與實際命令的引用必須一致。只有收據位置固定。本版只自動核對受審 profile 的正常觀測格式；其他資料保留待覆核。',
                'collection_note': '優先取得既有正常工程材料；故障日誌可另供症狀調查，但不是解除這項 PC3 缺口的必要材料。不要求漏洞重現、特殊攻擊輸入，也不要求現場補件。',
                'truth_note': '時間、命令、退出碼、輸出及 hash 均照原始紀錄填寫；不能為符合範例而改寫。受控本機觀測不代表客戶設備已驗證。'}}
