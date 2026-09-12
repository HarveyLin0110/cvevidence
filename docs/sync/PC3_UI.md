# PC3 UI／報告接線

更新：2026-09-12。基底 `origin/main` = `256fe2c`；分支 `codex/pc3-ui`。
Worktree：`/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/worktrees/pc3-ui`。

## 已完成

- 工程頁沿用核心 `condition_groups.condition_ids`，v2 明示 PC2 成品實作／靜態路徑與 PC3 部署／運作的差別；每個條件保留核心狀態及說明，沒有另算 PC verdict。
- 五個 Query ID 不變；UI／文字報告優先取 `query.title`、其次 `query.metadata.title`，無標題的舊紀錄仍採舊標籤。也呈現核心 `pc_layer`。同 ID 有多筆結果時不任選一筆，畫面與報告都保留重複警示。
- `runtime_observation` 顯示保存狀態、證據基礎、description、provenance；受控環境與用戶材料均不宣稱實體客戶 FW 認證。舊 run 沒有欄位時不補造 MISSING，也不重解釋舊 PC3。
- `followup_queries` 在工程頁「待補資料與覆核」及報告顯示 RULE_GAP、問題／理由、目標條件、所需檔案、狀態、引用及 context。格式／context 不符或重複 ID 時不顯示其內容，仍保留工程結果。
- AI tasks 明示 MODEL；`ASK_USER + COMPLETED` 顯示「等待用戶補件／補件要求已提出」。LIST／READ 等動作完成不顯示為條件成立；拒絕提案不當作有效補件建議。

## 比較 API 接法

`compare_analyses(..., include_followup_queries=True)` 才增加 `followup_query_changes`；預設輸出 key 維持相容。每列包含 query_id、change（ADDED／REMOVED／UPDATED）、before_status／after_status、before／after；依核心 query_id 配對，只改 context 不列差異。缺欄位的舊 run 視為未提供追加 Query。沿用同 product／release／build／artifact、CVE 與 context 檢查，呼叫端仍須核對 parent lineage。

整合端若要在現有前後比較 UI 顯示此欄位，請在自己負責的 `workspace.py` 呼叫加 `include_followup_queries=True`。此分支依任務範圍未改該檔、core_service.py、ai_service.py、核心或 Demo builder。

## 驗收

- 呈現聚焦：`env -u OPENAI_API_KEY -u OPENAI_MODEL work/.venv/bin/python -m pytest -q tests/test_analysis_view.py tests/test_analysis_report.py tests/test_integrated_presentation.py tests/test_pc3_presentation.py` → **36 passed，11.90 秒**。
- 新增 `tests/test_pc3_presentation.py`：PC2 支持但 PC3 未知、五種運作狀態、v1／缺欄位相容、保存 Query title／metadata、RULE_GAP scope／重複 ID／拒絕、MODEL 等待用戶、追加 Query 前後狀態及新增項、只換 context 不報差異、資料不被 renderer 改寫。
- 完整測試：`env -u OPENAI_API_KEY -u OPENAI_MODEL work/.venv/bin/python -m pytest -q` → **201 passed、23 subtests passed、1 warning，110.78 秒**；warning 是既有 ZIP 重複檔名拒收測試。`git diff --check` 通過。測試環境位於忽略的 `work/.venv/`，不納管。
- 依 15:28 收尾指示，真包與新版核心聯合驗收交由整合端接手；本分支僅檢視核心實際 `title`／`pc_layer` 與追加欄位格式，未代做真包驗收。
- 上述為 TEST_ONLY 呈現／scope 驗收，不代替真實 CVE、部署、來源認證或 LIVE 驗收。未呼叫 OpenAI API，未 push／merge／deploy。
- 對應 D01／D02／D06–D09，R01／R04–R06／R11／R12；涵蓋 A02／A11／A12／A14／A16 的呈現層案例，未宣稱完成其全鏈路驗收。
