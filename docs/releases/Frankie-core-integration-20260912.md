# Frankie × Horace 真實接線驗收
日期：2026-09-12。核心基線 Horace f577854；合入 commit 9e3e17a。此交付是 M5a 收件／來源／補件閉環；Q1–Q5、CVE 判定及 LIVE AI 尚未完成。

## 已接入
- Web/CLI → Runner.start_file → 固定 core_worker → Horace ingest_package/discover_candidates。
- Runner.source_tool → list_sources/search_sources/read_excerpt+verify_excerpt/compare_sources。
- Runner.supplement_file → validate_supplement → 新 archive/context/run；文字由 interpret_statement 作未驗聲明。
- 真實 manifest 決定 product/release/build；source_id/context_hash 與 evidence facts 分開保存；候選不等於受影響或症狀原因。
- 工程/AI 各自 NOT_RUN，assessment=null；UI 未交付操作反灰，已交付步驟有下一步及補件入口。
- CLI import/delta 與 Web 共用 Runner；legacy run/supplement 保留相容測試，不是新真實入口。

## 契約與限制
v0.2 envelope 加入可選 context_hash、sources、candidates、engineering_status、ai_status 與 DELTA，保留舊 run 可讀。format 支援 rom/cmake/curl。空 cve_id 用於候選探索，不准当完成判定；問題上限放寬至 100，正式 InvestigationTask／條件狀態仍待共同定義。
archive 最大 512 MiB，串流保存在 private blob；Horace 解包限制 2 GB／40,000 entries。原文最多 200 行及核心文字大小限制，每次重驗 archive/manifest/context。
worker 不接收提交資料指定模組、shell、URL，不繼承 API/OAuth secrets；仍不是 OS sandbox。多個核心呼叫共用期限，檔案搬運受大小限制但沒有獨立可取消 I/O。
父 run 不覆寫；不是防本機管理者的簽章/WORM。手動工具查詢尚未保存逐次 audit log；正式 AI 工具事件與引用語意驗證仍待後續。

## 真實資料驗收
Horace 原始三版 catalog 的 download_url 尚未填寫，此機器未取得他的完整包。直接使用他今天的 builder、upstream-lock 與官方新下載來源，重新建立：
- zlib 1.2.12 build：cmake-20260912T045733-3b4af5。
- zlib 1.2.13 build：cmake-20260912T045738-c489a0。
- 新版 frankie-cmake-integration-20260912，不是他電腦的 fresh-cmake-r2 binary，也沒有使用舊 Demo。
- hash／大小／manifest 見 data/catalogs/frankie-cmake-integration-20260912.json；完整包僅放 var/artifacts。
- 04、05、06 三包收件 3/3；06 補件 260→409 份來源，新增149，無移除／修改舊來源。
- parent：7c37dc80-6205-417f-9b13-f7e13a7061a1；child：358e8a50-08ec-4c39-8269-513f7d6002da。
- 父 run bytes 不變；錯 build 補件拒收；list/search/excerpt/compare 和報告通過。
- 原文讀取 source/update_reader.c，inflate 搜尋有命中；工程判定/AI 均 NOT_RUN。

## 操作與重跑
1. 開 localhost:8505，產品樣品選 06_cmake（本機新資料版），CVE 可以空白。
2. 匯入 → 確認 → 來源調查，可搜尋／原文／比較。
3. 到報告與補件，可直接套用已取得的同 build 補件，或上傳 supplement_06_cmake.tar.gz。
4. 新 run 保存 parent 和新增來源；側欄可載入歷史。

命令：
```bash
python -m pip install -r requirements.txt
PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python scripts/export_contracts.py
PYTHONPATH=src python scripts/validate_runner_integration.py data/catalogs/frankie-cmake-integration-20260912.json
PYTHONPATH=src python -m streamlit run runner_app.py --server.address 127.0.0.1 --server.port 8505
```

實包驗收需有 catalog 所列 archive。CI 不下載／執行样品，只用今日合成邊界材料呼叫真實 parser；共51項測試通過，唯一 warning 是刻意重複 ZIP member 的拒收測試。
覆盖 >20 MiB、blob 竄改、跨來源、catalog mismatch、錯 build、逾時、delta、CLI、AppTest 原文／下一步／文字補件。

## 安全與後續
對應 D01/D03/D06/D07/D09：核心基線、今日來源、artifact 排除、commit/PR/同步；R01/R03/R07/R11/R12：run scope、唯讀工具、失敗不冒充結果、parent lineage、安全文字呈現。
未完成：Frankie 側 ROM/curl 實包驗收、Q1–Q5/Verifier/Claim/條件、AI/LIVE、工程九格、多人授權與公網正式服務。公開 mockup 不是此本機資料服務。

