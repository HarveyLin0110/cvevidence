"""Generic input inventory and investigation plan; never certifies a new CVE."""
from .evidence import EvidenceBuilder, QUERY_IDS
from .integrity import digest
from .public_cve import record_url, brief

PROFILE_VERSION = 'general-cve-triage-v1'
PURPOSES = [
    '確認公告所指產品／元件與版本是否出現在本次成品中。',
    '確認相關功能設定、建置紀錄與交付成品是否屬於同一 build。',
    '依公告與上游修補，找出需核對的實作、修補狀態與必要條件。',
    '核對相關原碼是否進入交付成品，以及處理外部輸入的靜態路徑。',
    '確認同一成品實際部署的設定、正常操作紀錄及相關服務行為。',
]
MATERIALS = [
    '產品型號／韌體版本、SBOM 或元件清單。',
    '同 build 編譯紀錄、功能設定與成品識別資料。',
    '相關原始碼、上游修補差異或供應商修補說明。',
    '同成品的連結／來源對應資料及相關輸入處理原碼。',
    '部署設定、現有正常操作日誌／指令結果／封包或截圖及成品識別；不要求重現攻擊。',
]


def _matches(path, index):
    name = path.lower()
    return (
        ('sbom' in name or 'version' in name or 'manifest' in name),
        (name.startswith('build/') or 'config' in name or 'cmake' in name),
        (name.startswith('source/') or name.endswith(('.c', '.h', '.cpp', '.patch', '.diff'))),
        (name.startswith(('source/', 'product/', 'images/')) or name.endswith(('.map', '.a', '.so'))),
        (name.startswith(('runtime/', 'observations/')) or name.endswith(('.pcap', '.pcapng', '.png', '.jpg'))),
    )[index]


def plan(cve_id, context=None, public_record=None):
    record_url(cve_id)
    info = brief(public_record) if public_record is not None else None
    if info and info['cve_id'] != cve_id:
        raise ValueError('Plan CVE mismatch')
    targets = '、'.join(a['vendor'] + ' ' + a['product'] for a in (info or {}).get('affected', [])[:3])
    rows = []
    for index, qid in enumerate(QUERY_IDS):
        materials = sorted(({'source_id': r['source_id'], 'path': r['path']} for r in context.sources.values()
                            if r['kind'] == 'file' and _matches(r['path'], index)), key=lambda r: r['path']) if context else []
        rows.append({'query_id': qid, 'title': PURPOSES[index], 'description':
                     (('公告目標：' + targets + '。') if targets else '') + PURPOSES[index],
                     'pc_layer': ['PC1', 'PC2', 'PC2', 'PC2', 'PC3'][index],
                     'materials': MATERIALS[index], 'available_sources': materials[:12],
                     'available_source_count': len(materials), 'source_list_truncated': len(materials) > 12,
                     'status': 'PLANNED' if context is None else 'MATERIALS_AVAILABLE' if materials else 'WAITING_EVIDENCE',
                     'reason': '尚無已審查的 CVE 條件規則；先查閱現有材料，再由 AI 提出具體問題供工程覆核。',
                     'verification_status': 'NOT_RUN'})
    return {'cve_id': cve_id, 'status': 'GENERAL_TRIAGE', 'queries': rows,
            'message': '此 CVE 尚無已審查的專用規則；將盤點材料、取得公開公告並啟用通用調查。條件未驗證前維持需要進一步調查。',
            'note': '材料分類只供安排調查；檔名命中、公告與版本關聯都不代表條件成立。',
            'public_record': info}


def collect(context, cve_id):
    context.assert_current()
    prepared = plan(cve_id, context)
    b = EvidenceBuilder(context)
    for row in prepared['queries']:
        qid = row['query_id']
        b.emit(qid, 'inventory_' + qid, {'file_count': row['available_source_count'],
               'content_verified': False}, [s['source_id'] for s in row['available_sources']],
               '僅盤點本次已收件檔案；尚未核對其內容是否支持此 CVE 的條件。')
        b.gap(qid, row['reason'])
        b.queries[qid].update(status='AWAITING_RULE_REVIEW', description=row['description'],
            metadata={'gap_kind': 'CAPABILITY_GAP', 'verification_status': 'NOT_RUN',
                      'available_source_count': row['available_source_count'], 'materials': row['materials']})
    b.runtime_observation.update(status='AWAITING_EVIDENCE',
        description='尚未建立此 CVE 的運作證據驗證規則；已提交檔案也須查閱與覆核，不能直接判定有效。')
    return b.result(cve_id, PROFILE_VERSION)


def assess(context, verified, statements=()):
    from .assessment import LABELS
    conditions = [{'condition_id': key, 'title': '公告產品／元件與版本' if key == 'component' else title, 'state': 'UNKNOWN', 'evidence_ids': [],
                   'explanation': '此 CVE 的必要條件與驗證規則尚待建立；目前只有材料盤點，尚未完成此項驗證。'}
                  for key, title in LABELS.items()]
    notes = []
    for note in statements:
        text = note if isinstance(note, str) else note.get('text', '')
        notes.append({'text': text, 'blocks_verdict': True, 'verified_engineering_fact': False,
                      'statement_id': ('M-' + digest(text)) if isinstance(note, str) else note.get('material_id', note.get('statement_id')),
                      'source_context_hash': context.context_hash if isinstance(note, str) else note.get('source_context_hash', context.context_hash),
                      'reason': '使用者補充只作調查線索，待工程覆核。'})
    result = {'schema_version': '1.0', 'cve_id': verified.cve_id, 'profile_version': PROFILE_VERSION,
              'context_hash': context.context_hash, 'assessment_kind': 'GENERAL_TRIAGE',
              'cve_condition_verification_status': 'NOT_RUN', 'inventory_status': 'COMPLETED',
              'verdict': 'NEEDS_INVESTIGATION', 'conditions': conditions, 'conflicts': [],
              'reason': '已完成交付材料盤點；此 CVE 尚無已審查的條件驗證規則，需依公開公告與產品證據繼續調查。缺口包含工具能力，不只是使用者缺件。',
              'gaps': [{'query_id': q['query_id'], 'needed': q['missing'][0], 'kind': 'CAPABILITY_GAP',
                        'same_build_required': False} for q in verified.queries],
              'next_steps': ['查看本次查核計畫與公開 CVE 公告，確認公告所指產品／元件。',
                             '啟動 AI 查閱已提交資料，列出具體查核問題、依據與仍需補充的最小材料。',
                             '工程師覆核漏洞必要條件與證據；專用驗證尚未完成前維持待調查。'],
              'statement_reviews': notes, 'statement_context': notes, 'blocked_conditions': [],
              'evidence_ids': [r['evidence_id'] for r in verified.records],
              'source_advisories': [record_url(verified.cve_id)], 'human_review_required': True,
              'provenance_verified': False, 'symptom_causation': 'NOT_ESTABLISHED',
              'verification_hash': verified.collection_hash,
              'scope': '本次完成的是成品材料盤點與通用調查；CVE 條件驗證未執行。AI 與公開公告不能直接產生受影響或不受影響的判定。'}
    result['assessment_id'] = 'A-' + digest(result)
    return result
