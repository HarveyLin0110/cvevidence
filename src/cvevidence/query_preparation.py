"""Read-only presentation of the current core's CVE-specific query work; no verdict planner."""
from cvevidence_core.catalog import CATALOG
from cvevidence_core.queries import FORMAT, PROFILE_VERSION
from cvevidence_core.evidence import QUERY_IDS
from .query_display import LEGACY_TITLES, V2_PURPOSES

PURPOSES = {
    'CVE-2014-0160': {
        'Q1_COMPONENT':'核對 OpenSSL 實際版本與原始碼；Heartbleed 公告範圍為 1.0.1–1.0.1f 與 1.0.2-beta1，1.0.1g／1.0.2-beta2 修正。',
        'Q2_BUILD':'核對 ROM、產品、SDK 與編譯紀錄是否屬於同一 build，擷取實際功能旗標。',
        'Q3_IMPLEMENTATION':'核對 tls1_process_heartbeat 與 TLS dispatch 是否編入，及 OPENSSL_NO_HEARTBEATS 是否有效排除兩處。',
        'Q4_BINDING':'核對 device-management → libssl → object／source 綁定、ROM 範圍，以及 SSL_accept／SSL_read 到 heartbeat dispatch 的靜態路徑。',
        'Q5_PATH':'核對同成品與 libssl 的運作收據、正常 TCP/TLS 1.2 交互紀錄；缺件追加要求，不發送攻擊封包。'},
    'CVE-2022-37434': {
        'Q1_COMPONENT':'核對 zlib 版本標頭與 inflate.c；此 profile 深入審查 1.2.12 與修補版 1.2.13。',
        'Q2_BUILD':'核對 CMake 成品、編譯紀錄與功能設定是否屬於同一次建置。',
        'Q3_IMPLEMENTATION':'核對 gzip EXTRA 複製的 len／extra_max 邊界與已審查修補。',
        'Q4_BINDING':'核對 update-reader → libz.a → source 綁定，以及 inflateGetHeader、extra buffer 與分段輸入條件。',
        'Q5_PATH':'核對同成品收據、正常 gzip 樣本與原始輸出，包括 CRC／長度；未提供則追加補件問題。'},
    'CVE-2023-38545': {
        'Q1_COMPONENT':'核對 curl／libcurl 元件與已審查 8.3.0 原始碼。',
        'Q2_BUILD':'核對安裝成品、libtool／編譯紀錄与同 build 功能設定。',
        'Q3_IMPLEMENTATION':'核對 SOCKS5 hostname 狀態機與已審查修補。',
        'Q4_BINDING':'核對 launcher、libcurl 與成品綁定，以及 URL／hostname 與 buffer 的靜態分支。',
        'Q5_PATH':'核對同成品運作收據、SOCKS5 原始交互及 remote DNS／buffer 配置；缺件追加問題。'},
}

MATERIALS = {
    'CVE-2014-0160': {
        'Q1_COMPONENT':'OpenSSL 版本標頭與已審查 source/openssl 原始碼。',
        'Q2_BUILD':'build/build-record.json、同次 compiler argv、ROM／成品身分。',
        'Q3_IMPLEMENTATION':'t1_lib、s3_pkt 的同 build 編譯與預處理輸出（build/*.i）。',
        'Q4_BINDING':'images/device.rom、product/device-management、SDK libssl、archive／object／linker map、source/device.c。',
        'Q5_PATH':'runtime/observation.json 及收據引用的原始 TCP／TLS 紀錄；須綁定相同成品與 libraries。'},
    'CVE-2022-37434': {
        'Q1_COMPONENT':'zlib.h、source/zlib/inflate.c。',
        'Q2_BUILD':'build/build-record.json 與 CMake 實際編譯設定。',
        'Q3_IMPLEMENTATION':'已審查 inflate.c 及修補版本對應內容。',
        'Q4_BINDING':'product/update-reader、build/cmake/zlib/libz.a、object／linker map、source/update_reader.c。',
        'Q5_PATH':'runtime/observation.json、其引用的 gzip 樣本與原始輸出；核對檔案 hash、CRC 與解碼長度。'},
    'CVE-2023-38545': {
        'Q1_COMPONENT':'curl 版本與已審查原始碼。',
        'Q2_BUILD':'build-record、libtool／編譯設定與標頭依賴。',
        'Q3_IMPLEMENTATION':'source/curl/lib/socks.c 與修補對照。',
        'Q4_BINDING':'安裝成品、libcurl、launcher、URL parser／buffer 設定與連結紀錄。',
        'Q5_PATH':'同成品 runtime 收據、SOCKS5 原始交互與配置檔。'},
}

def prepare_queries(cve_id, package_format=None):
    cve_id = cve_id.strip().upper()
    if cve_id not in CATALOG:
        from cvevidence_core.general_triage import plan
        return plan(cve_id)
    mismatch = package_format is not None and package_format != FORMAT[cve_id]
    rows = []
    for qid in QUERY_IDS:
        rows.append(dict(query_id=qid,title=LEGACY_TITLES.get(qid,qid),
            description=PURPOSES.get(cve_id,{}).get(qid,V2_PURPOSES.get(qid,'需由核心提供此新增項目的用途。')),
            materials=MATERIALS.get(cve_id,{}).get(qid,'依核心規則提供同成品材料。'),
            pc_layer={'Q1_COMPONENT':'PC1','Q2_BUILD':'PC2','Q3_IMPLEMENTATION':'PC2','Q4_BINDING':'PC2','Q5_PATH':'PC3'}.get(qid,'核心尚未提供分層'),
            status='FORMAT_GAP' if mismatch and qid!='Q2_BUILD' else 'PLANNED'))
    return dict(cve_id=cve_id,status='FORMAT_GAP' if mismatch else 'READY',queries=rows,
        profile=PROFILE_VERSION,format=FORMAT[cve_id],sources=CATALOG[cve_id]['sources'],
        message=('目前資料格式不符此 CVE 已審查格式；只可核對建置身分，其餘將記錄缺口。' if mismatch else
                 '依本次 CVE 與目前核心規則準備，尚未執行；資料缺口與追加 Queries 由實際查核後決定。'))

def render_preparation(st,cve_id,package_format=None):
    plan=prepare_queries(cve_id,package_format)
    st.subheader('準備執行的 Queries')
    st.text(plan['cve_id']+' · '+plan['message'])
    if not plan['queries']: return plan
    if plan['status']=='GENERAL_TRIAGE':
        st.caption('將向 CVE 公開 API 查詢此編號；只送出 CVE ID，不送出產品檔案。盤點後再依公告與現有材料細化計畫；模型調查另由 AI 步驟啟動。')
    else:
        st.caption('目前各已支援 CVE 共用查核類別，但查核內容、規則與所需材料依 CVE 決定；不是 AI 任意生成的測試。')
    for q in plan['queries']:
        status='格式尚未支援' if q['status']=='FORMAT_GAP' else '待執行'
        with st.expander(q['query_id']+' · '+q['pc_layer']+' · '+status,expanded=True):
            st.text('查核內容：'+q['description'])
            st.text('所需材料：'+q['materials'])
    st.caption('執行只讀交付材料，不執行上傳程式或漏洞攻擊；正式結果見執行後紀錄。')
    return plan
