"""Explain saved Heartbleed conditions; do not compute an alternative verdict."""
ADVISORY = 'https://openssl-library.org/news/secadv/20140407.txt'

def openssl_context(entry,group):
    if entry.get('cve_id') != 'CVE-2014-0160': return ''
    assessment=entry.get('assessment') or {}
    if not str(assessment.get('profile_version','')).endswith('-runtime-v2'): return ''
    conditions=assessment.get('conditions') or []
    if len({c.get('condition_id') for c in conditions}) != len(conditions): return ''
    states={c.get('condition_id'):c.get('state') for c in conditions}
    if group=='PC1':
        component=next((c for c in conditions if c.get('condition_id')=='component'),{})
        ids=component.get('evidence_ids',[])
        records=[e for e in entry.get('evidence',[]) if e.get('evidence_id') in ids and e.get('fact_key')=='component']
        lead=''
        if len(records)==1 and states.get('component')=='SUPPORTED':
            value=records[0].get('value')
            if isinstance(value,dict) and value.get('confirmed') is True and value.get('name')=='openssl' and value.get('version')=='1.0.1f':
                lead='本次工程證據核對到 OpenSSL 1.0.1f，落在 Heartbleed 的公告受影響版本範圍。'
        return lead+'公告範圍為 OpenSSL 1.0.1～1.0.1f，以及 1.0.2-beta1；1.0.1g／1.0.2-beta2 修正。不能概括為所有更舊版本都受影響，也不能只用版本判定此成品；仍須核對 PC2 與 PC3。公告：'+ADVISORY
    if group=='PC2' and all(states.get(k)=='SUPPORTED' for k in ('vulnerable_implementation','entry_reachable','trigger_prerequisites')):
        return '本次保存的實作與靜態路徑條件均獲支持：heartbeat 處理函式及 TLS dispatch 已編入，沒有以 OPENSSL_NO_HEARTBEATS 有效排除；產品的 SSL_accept／SSL_read 路徑可到達 heartbeat 處理。以下是對應工程證據，不是實際攻擊成功紀錄。'
    if group=='PC3':
        runtime=entry.get('runtime_observation') or {}
        if states.get('runtime_observation')=='SUPPORTED' and runtime.get('status')=='VERIFIED':
            if runtime.get('evidence_basis')=='CONTROLLED_LOCAL_OBSERVATION':
                return '同一成品與 OpenSSL library 的受控本機 TCP／TLS 1.2 正常交互紀錄已通過核心核對，支持目前 profile 要求的運作條件。觀測限於本機環境，未證明客戶設備對外暴露，也未進行 Heartbleed 攻擊重現。'
        if states.get('runtime_observation')=='UNKNOWN':
            return '尚不能确认同成品實際如何運作；請補 runtime/observation.json 與其引用的 TLS 原始交互紀錄，讓核心核對成品、library、命令與正常連線結果。'
    return ''
