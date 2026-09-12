# Horace 開發同步

更新：2026-09-12 15:48（Asia/Taipei）。Horace 只維護本檔，Frankie 維護自己的同步檔；詳細測試歷史放交件報告，不在此重貼完整對話。

## 最新決定：先實作與 Demo，講稿暫緩

- 使用者修正：現場兩版 Demo；第一版資料齊全直接確認有影響，第二版需要補件，只展示 AI 提供「缺什麼、為何需要、如何取得」後結束。**第二版不在現場補件上傳或重新判定**。這取代較早文件要求現場完整補件閉環的展示安排；後端補件能力仍保留驗收。
- 新輸入位於 `demo-inputs/two-flows/`，兩個獨立初始包使用今日同一個 CMake 成品。第一版已在包內備妥運作資料；第二版只有 PC2。catalog 可直接由現有網頁樣品索引讀取，沒有另建 API 或重写前端。
- 本分支 `codex/horace-v2-acceptance` 已合入 PR #20 `da0a4c2` 與 PR #22 `1ca3834`，固定組合 `46b8904`。兩包真 Runner 已分別得到 Affected／Needs Investigation；第二版 Live 為 Sol／medium，4 calls、32.968 秒 → NEEDS_USER_INPUT；沒有補件或重判。兩版實際 Runner 16／16、實際保存結果 UI 呈現 7／7、完整 pytest 239 passed＋23 subtests（300.40 秒），schema 一致。這是本機固定組合驗收，網站仍需整合發布。
- 前一個固定預覽核心 `3ddb6dc`＋Runner `30719a3` 的三格式／歷史驗收為 43／43；新版修補後另跑，不冒稱預覽是公開站版本。第一版基線完整測試為 197 passed、23 subtests，165.34 秒；不當成第二版測試數。

## 可立即接線的版本

- 核心 `7b24110` 已隨整合 PR #17 進 main `256fe2c`；固定整合基線 `c65e9c7` 的 `src/cvevidence_core` 與 Horace 當時核心相同。原 PR #9 最新 `d3211da` 另含 ROM 網站驗收文件，合併狀態以 GitHub 為準。
- **網站 API 已真正接通**：15:16，HTTPS 團隊站頁面版本 `5918858`，工程 run `0a700c0f-0a94-481d-b7b9-23e3aecf6ec4` 追加 AI ID `b4565c59-ee92-492b-93ea-1a22b36e65c3`，`gpt-5.6-sol` 真實 5 calls，LIVE／NEEDS_USER_INPUT。AI 區分截短檔案線索與 CVE 適用性，要求同 build source／libz.a／link 及客戶檔案雜湊。之前 ea5e571 的未接線狀態是歷史，不再代表現站。
- 本機 key 不隨 Git 傳送；網站由服務主機的可信設定取得金鑰。本輪只從網站觸發既有 AI worker，沒有複製金鑰或修改部署。
- **修正提案 `codex/horace-integration-history`**：真 Runner 重現「NOTE 指出未交付入口→工程 DELTA→前文消失」；現在沿同 scope parent 鏈傳回原文字／M-ID／來源 context，再由核心重核；歷史頁也恢復原現象。涉及 Frankie 接線，獨立分支交審，未自行部署。詳見 `docs/releases/Runner_補件歷史接線修正_2026-09-12.md`。
- Git 的 `demo-inputs/` 已在 main：9 初始包＋3 同 build 補件，12 包 hash 通過，約 95 MB。主展示原版為 ROM 03→supplement_03；PC3 新展示另由側邊協調工作建立，不混為已驗收。
- 已收到側邊分工：PC1–PC3 是查核面向，PC3 的實際部署／運作證據允許缺件，由 AI 依缺口新增 Query／補件要求，驗證後重判並保留歷史。側邊在 `var/worktrees/pc3-query-evolution` 實作核心與今日新 Demo；本分支避開其核心改動，維持歷史接線與真實網站驗收。

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

- 本次歷史接線分支以整合基線 c65e9c7 執行 **193 passed、23 subtests，170.96 秒**；契約重產一致。包含真 CMake NOTE→DELTA、ROM 聲明重新核對、不可變歷史、scope／損壞拒收與歷史頁情境回填。網站 Live／CMake 補件紀錄見 `docs/releases/團隊站_CMake_Live_實測_2026-09-12.md`。

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

D 的 integration a47a1a3 未接分析屬當時結果，main 新 OFFLINE 已取代該狀態；c65e9c7 已接 PC／excerpts 與 Live worker，網站具名验收見上方。A/B/C/D 第一、二輪均已交件，不作為仍活躍名額。新的網站 Live 及歷史接線狀態以本檔最上方為準；舊 consumer 結果不替代新版本驗收。

本環境無跨對話讀／發訊工具，透過 worktree MD、Git commit 與 PR 收件，不宣稱已自動傳訊。使用者授權最多主線之外三個活躍工作，依需要續派；側邊協調者管理任務。heartbeat cvevidence 每五分鐘補巡檢，17:35 截止，完成／叫停後停用。

## 存放

輸入 `demo-inputs/`；程式 `src/cvevidence_core/`；builder `tools/demo-data/`；可公開驗收 `docs/releases/`；完整 build/artifact/run/report 留忽略的 var 下。只 stage 本人改動，不強推，不把新原始客戶資料／key 上 Git。由整合負責人審查確切 head 後合 main。

逐項責任與剩餘聯合驗收見 `docs/releases/Horace_責任驗收與剩餘接線.md`。
