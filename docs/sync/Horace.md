# Horace 開發同步

更新：2026-09-12 14:56（Asia/Taipei）。Horace 只維護本檔，Frankie 維護自己的同步檔；詳細測試歷史放交件報告，不在此重貼完整對話。

## 可立即接線的版本

- 最新產品 checkpoint：**`7b24110`**，分支 `codex/horace-fresh-core`，[PR #9](https://github.com/HarveyLin0110/cvevidence/pull/9)。已合回 main `9d11d48` 的 OFFLINE 工作台；沒有覆改 Frankie 的產品程式。PR 最新 head／CI 以 GitHub 即時狀態為準。
- Git 的 **`demo-inputs/` 已在 main**：9 初始包＋3 同 build 補件，12 包 hash 通過，約 95 MB／最大 17 MB。主展示先 `rom/03_rom.tar.gz`，再從補件入口傳 `rom/supplement_03_rom.tar.gz`。配對與可貼文字見該資料夾 README。
- **團隊 HTTPS 站已實測工程補件流程**：頁面 SHA `ea5e571`；Horace 真 Chrome 操作 ROM 03 → Needs Investigation → 同 build 補件 → Not Affected → 前後比較，重新載入後原報告文字完全保留。原工程 run `2181d491`、補件後 `c4b39a19`。詳見 `docs/releases/團隊站_ROM_實測_2026-09-12.md`。初判下載收到事件；補件後下載事件逾時，待確認。未重啟服務。
- **網站 Live 仍未接入**：第 04 步實際為 OFFLINE 並明示未接線。本機 key 不隨 Git 同步；網站主機需可信設定與獨立 AI worker／stage 保存。ea5e571 畫面及報告仍未直接呈現 evidence.excerpts。main 最新查得 `e9cc996`；PR #9 `9863b1b` 當時 CI 成功、CLEAN，尚未合併。
- 本輪不是要求隊友重做 Query／規則／AI：使用 `src/cvevidence_core/` 的現成入口即可。完整語意及樣例見 `docs/architecture/核心分析介面與接線提案.md`。

## 責任與固定限制

| Horace | Frankie／整合端 |
|---|---|
| 新 builder、真實正常觀測、9＋3 輸入包 | 正式收件與工作台 |
| parser、五 query、原文工具、Verifier | Runner、進度、錯誤映射、共用 contracts |
| 三 CVE profile、規則、Claim、缺口與中文摘要 | 結果呈現、報告／下載 |
| OpenAI 動態調查、引用重核與補件內容 | Live／Offline／Replay 入口、可信設定、整次程序期限 |
| 同 build 材料驗證、文字語意及重判 | 不可變 snapshot、parent run、保存與前後比較 |

今日團隊程式、builder、測試與資料全部重新製作。舊 DOCX／Demo 只看概念；公開 OSS 今日從官方重新取得並保留 hash／授權。唯一根目錄是 Fresh，棄用目錄已移至垃圾桶。給隊友的文件使用繁體中文。

分析只讀當次交付，不執行匯入 binary，不讀 factory、測試答案、其他包或未提交補件。人工／AI 文字不直接改已驗條件；初判限定目前成品／profile，保留人工覆核。內部 hash 一致不是供應商認證或實際部署暴露證明。

使用者選 `gpt-5.6-sol`／`medium`，真實 API 已成功。key 由可信程序讀環境或忽略的 `.env.local`，不進 Git。OFFLINE、LIVE、REPLAY、SIMULATED 分開標示。

## 核心與前端接線

1. 工程：`frankie_adapter.analyze_archive_for_runner(archive_path, options, expected_archive_sha256=..., expected_context_hash=..., ...)`；既有 worker 已解包時用 `workflow.analyze_package(context, mode="OFFLINE", ...)`。原 collect/read v0.2 保持相容。
2. 工程先保存，再用 **`workflow.investigate_after_engineering(context, saved_engineering_result, ...)`** 啟動 Live。AI 失敗保留原工程 dict；呼叫端不必重貼已保存文字，核心會從 assessment 取出歷史聲明供 AI 閱讀。仍可用 user_context 傳當次新問題。
3. AI 新原文只先成為 exact-bytes 來源觀測，再 collect→verify→assess。自由推論不升格成條件；未完成調查不偽裝重判成功。
4. 延後 AI 回傳是 stage wrapper，不能取代完整工程 JSON。依 context／CVE／內外 engineering_assessment_id 核對後組合顯示，保留工程及 AI 各自不可變紀錄；禁止補造 ID 通過 guard。
5. `analyses[].condition_groups` 提供共用前提與 PC1／PC2／PC3，僅供呈現，不改 assessment hash、Evidence ID 或判定。條件維持 SUPPORTED／BLOCKED／UNKNOWN，不轉成舊 TRUE／FALSE。
6. 新 Live 有 started_at／finished_at；Replay 有原時間、本次播放時間及 original_record_hash。舊紀錄若未存原時間，顯示未知，不以播放時間代替。
7. 原文鏈在 **`evidence[].excerpts`**：X-ID、source/file hash、行號與 text 已提供。現有 renderer/report 主要顯示 witnesses，請補呈現 excerpts 與同 scope 來源操作。分析與原文工具須使用同一核心版本，避免舊 X-ID 演算法混用。
8. 未支援 CVE 的 assessment/ai=null；即使外層程序 COMPLETED，也不能顯示安全。malformed tar 可拋 TarError，worker 需保留例外→失敗映射；收件前失敗未必有 stage event。

兩入口為「描述現象」與「指定最多五個 CVE」，候選、產品適用性、異常原因分開。五 query 為 Q1_COMPONENT／Q2_BUILD／Q3_IMPLEMENTATION／Q4_BINDING／Q5_PATH；AI 新問題不固定為 Q6。

03 來自 ROM 02、06 來自 CMake 04、09 來自 curl 07。同 build 補件不更換 binary，建立新 context；不同 build 不合入原案件。中性文字存 statement_context，不阻擋判定；未決／矛盾／新增範圍聲明才阻擋。後續足夠證據可解除歷史待查，原 M-ID／source context 保留。

## 最新驗收與限制

- 合回 main 的 `e887c00`：**165 passed、23 subtests，52.77 秒**；schema 重產一致。之後 `7b24110` 只補 AI 的保存文字上下文及專項驗收，50 項 AI／回流聚焦測試通過；7b24110 的 CI 34678280555 已通過：167 passed、23 subtests，45.22 秒（含當時 main 的合併檢查）；後續 head 以新 checks 為準。
- 九格工程 9/9、三組補件 3/3；C 另從 Git archives 獨立驗 9＋3 與九項邊界。三個展示輸入各十次共 30 次 OFFLINE，結果／ID 穩定。這些是具名既有驗收，不冒稱每個新 head 都重跑全部。
- A 中性／矛盾語意已整合。C 第二輪 ROM 文字、補件、重核與失敗隔離 **16/16**，原檔／結果保留，沒有新核心 blocker。
- B 第二輪 2 個模擬失敗保留通過；原兩筆 Live 一通過、一筆 8 calls 耗盡。主線 `dd47a1e` 修工具參數引導及剩餘預算提示後，同一原問題 **5 calls／44.872 秒完成**，8 筆新原文重核，仍 Not Affected。原失敗完整保留，不提高預算或放寬引用核對。
- `7479368` 新增未交付網路 gzip 入口：**4 calls／36.449 秒** → ASK_USER、工程待查，既有條件不變，Live／Replay 時間通過。必要補件與可選動態測試分開，漏洞重現不是必要交付。
- **`7b24110` 延後 AI，呼叫端 user_context 留空**：AI 自動讀保存的另一入口聲明，**4 calls／31.198 秒**提出兩項同 release／build 的最小材料；工程與歷史保留、重判仍待查、Replay 原時間與 PC 分組核對通過。證據在 `docs/releases/驗收證據/延後AI保留歷史聲明Live摘要.json`。
- 四個原始 Live 情境、注入／錯引用、真包 source 篡改／多 ELF／build 衝突另見完整交件及驗收證據。精確引用不等於語意證明；沒有宣稱全面防注入、所有 CVE 自動判定或部署安全。
- `9f3ac28` 已 pip 打包安裝，repo 外 site-packages 可載入 reviewed_sources.json 與 PC 分組。之後 7b24110 再次打包，repo 外 CLI 跑真 CMake 05：五 query／Not Affected，安裝 ai.py 與工作樹 bytes 相同，不新增依賴。

## 已接收的並行交件

| 工作 | 固定測試核心／結果 | Git 交付 |
|---|---|---|
| A 語意 | 真包文字／矛盾／同 build 重核已通過 | 已合入主線，原分支 codex/parallel-semantics |
| B 第二輪 Live | 44efc7b；含成功、耗盡及模擬失敗，未掩蓋失敗 | 主線 848cb32／c1d0604／7853ed3；Parallel_AI_R2 報告 |
| C 第二輪回歸 | 44efc7b；16 PASS／0 FAIL | 主線 19a8b78／65789d2；Parallel_QA 報告 |
| D 指定 consumer | 44efc7b；基本 JSON／隔離通過，兩個原文呈現失敗 | 分支 codex/parallel-contract-qa，754e6a3；未混入最新產品通過數 |

D 的 integration a47a1a3 未接分析屬當時結果，main 新 OFFLINE 已取代該狀態；原文呈現與 Live 正式接線仍列給負責者。A/B/C/D 第一、二輪均已交件，不作為仍活躍名額。下一步優先固定最新整合版本做真實網頁／重啟／Live 保存驗收，避免重跑同版核心案例。

本環境無跨對話讀／發訊工具，透過 worktree MD、Git commit 與 PR 收件，不宣稱已自動傳訊。使用者授權最多主線之外三個活躍工作，依需要續派；側邊協調者管理任務。heartbeat cvevidence 每五分鐘補巡檢，17:35 截止，完成／叫停後停用。

## 存放

輸入 `demo-inputs/`；程式 `src/cvevidence_core/`；builder `tools/demo-data/`；可公開驗收 `docs/releases/`；完整 build/artifact/run/report 留忽略的 var 下。只 stage 本人改動，不強推，不把新原始客戶資料／key 上 Git。由整合負責人審查確切 head 後合 main。

逐項責任與剩餘聯合驗收見 `docs/releases/Horace_責任驗收與剩餘接線.md`。
