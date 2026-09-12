# Horace 開發同步

更新：2026-09-12 14:11（Asia/Taipei）。此檔只由 Horace 對話維護，Frankie 維護 `docs/sync/Frankie.md`。只保留影響協作的現況；變動共用介面前讀對方同步，不互相覆蓋。

## 現在可取得的交件

- **輸入包已在 main**：`demo-inputs/` 的 9 初始包＋3 同 build 補件隨 PR #2 於 13:34 合併。12 包 SHA-256 本輪全通過；約 95 MB，最大 17 MB，不需要 LFS。不要再等待 PR #2 或從舊 Demo 搬檔。
- **完整核心 PR #9**：https://github.com/HarveyLin0110/cvevidence/pull/9 。固定產品 checkpoint `44efc7bdcc533760ab167a2a005b0111b9758483` 已推送；Q1–Q5、verify/assess、Claim、中文摘要、AI 與同 build 補件重判均可接線。本輪將 main 基線合回作者分支，解 README／gitignore 衝突並補 CI 的 binutils、squashfs-tools；不改 Frankie 產品程式。
- **最短真實網頁路徑**：`demo-inputs/rom/03_rom.tar.gz` → `analyze_archive_for_runner(..., options={"requested_cves": ["CVE-2014-0160"], "mode": "OFFLINE"})` → 保存完整 JSON → 顯示工程結果。不要等額外 Live／長回歸才接 checkpoint。
- 完整介面：`docs/architecture/核心分析介面與接線提案.md`；展示選檔：`demo-inputs/README.md`；已有驗收：`docs/releases/Horace_完整核心與Demo交件.md`、`docs/releases/Parallel_QA.md`。

## 責任與已定限制

| Horace | Frankie／整合端 |
|---|---|
| 新 builder、真實觀測、9＋3 輸入包 | 收件 UI、Runner、工作台 |
| parser、Q1–Q5、來源工具、Verifier | 共用 contracts、執行進度及錯誤映射 |
| CVE profile、規則、Claim、缺口／摘要 | 結果呈現、保存與報告 |
| OpenAI 動態調查、引用核對與補件建議 | 模式入口、整次執行期限、可信設定注入 |
| 同 build 補件驗證、文字與矛盾語意 | 不可變 snapshot／parent run／歷史比較 |

團隊程式、builder、測試及資料全於今日重新製作；舊 DOCX／Demo 只看概念。公開 OSS 今日從官方重新下載並保留授權／hash。唯一根目錄為 `CVEvidence_Fresh_2026-09-12`；棄用目錄已移至垃圾桶。給隊友的文件用繁體中文。

核心只讀當次交付，不執行匯入 binary、不讀 factory／測試答案／其他包／未交補件。人工文字、模型推論與版本警示不能直接改判定。初判須人工覆核，來源 hash 一致不是供應商簽章或已證明實際部署。

使用者指定 `gpt-5.6-sol`／`medium`，實際 API 已成功。key 由環境或 Git 忽略的 `.env.local` 提供，不寫入同步／PR／結果。OFFLINE、LIVE、REPLAY 與 SIMULATED 必須分清。

## 介面與接線要點

1. **工程先完成**：`workflow.analyze_package(context, mode="OFFLINE", ...)` 或 file-backed `frankie_adapter.analyze_archive_for_runner(...)` 回傳完整 JSON。Runner 擁有 run ID、固定 archive/context、保存、parent 與執行外層期限。原 v0.2 collect/read 維持相容，沒有另做正式 Runner。
2. **後續 AI 獨立階段**：`workflow.investigate_after_engineering(context, saved_engineering_result, ...)` 重新核對來源與已保存判定；AI 逾時／錯誤不改原工程 dict。傳入 trusted `env_file` 或由可信程序讀環境，不能讓上傳資料決定 key 路徑。既有 intake worker 不傳 key；AI 階段需另外接入。
3. **JSON 保存提案**：完整工程 payload 具有 `context_hash` 與 `analyses[]`；每個 analysis 含 `cve_id`、queries、evidence、assessment、ai。舊 RunEnvelope 的 TRUE／FALSE 與 NOT_RUN 不可硬轉成新狀態；整合端以版本化 sidecar／envelope 保存。Frankie F14 renderer 可吃完整工程 payload，但正式保存位置與啟動入口仍由整合端確認。
4. **分階段 AI 的呈現**：AI 階段回傳項目只有 CVE、工程 assessment ID、ai、investigation_verification，不能單獨當完整工程 payload 傳給 renderer。保留原工程結果，依相同 context/CVE/assessment ID 組合顯示，AI 記錄另存不可變結果。
5. **五 query 與動態問題**：Q1_COMPONENT／Q2_BUILD／Q3_IMPLEMENTATION／Q4_BINDING／Q5_PATH。AI 依內容新增不同問題、READ／SEARCH 等工具或 ASK_USER，不硬編固定 Q6。新原文经 exact bytes 重核為來源觀測，再 collect→verify→assess；自由推論不升格為條件。
6. **狀態不能混用**：condition 為 SUPPORTED／BLOCKED／UNKNOWN；未執行或完整性失敗 assessment=null。未知 CVE 保留 UNSUPPORTED，即使外層程序 COMPLETED 也不能顯示安全。malformed tar 可拋 `tarfile.ReadError`，整合 worker 必須保留 TarError 映射。
7. **文字語意已修**：中性「已提供檔案」保留 `statement_context`，不阻擋正式條件；只有未決／矛盾／新增範圍工程主張進 `statement_reviews`。同 build 補件可由新證據解除舊待查主張，但不信任傳入的 verified flags。

兩入口：先描述現象可沒有 CVE／檔案；或指定最多五個 CVE，逐個分析。候選、適用性、異常根因分開。03 來自 ROM 02、06 來自 CMake 04、09 來自 curl 07；補件不更換 binary，不跨 build 合併。

## 已有證據與仍待完成

- 產品 checkpoint `44efc7b`：75 項 unittest 通過，28.871 秒。早先乾淨 venv 已驗安裝與 package-data；不把早期安裝測試冒稱新合併版全部通過。
- 九格工程 9/9、三組補件 3/3；C 另從 Git archives 獨立驗 9＋3 與九項邊界。ROM 03 adapter 第一笔結果 2.104 秒，11 項核對通過；這是核心 adapter，尚非實際網頁。
- ROM 03、CMake 04、curl 09 各十次 OFFLINE，共 30 次；verdict、Assessment ID、Evidence ID 穩定。真包 source 篡改、多 ELF、build 衝突均回 Needs Investigation。
- 原四個 Sol／medium 真實 Live 情境通過。整合 A/B 後追加 CMake 05＋中性文字 → Not Affected → 真實 Live → 4 筆新來源觀測 → 重判 Not Affected，文字歷史仍保留。摘要在 `docs/releases/驗收證據/整合後分階段Live摘要.json`。
- A 語意修正已合入 `15f53a4`；B AI 可靠性合入 `08dee40`、`5ff192d`；C 獨立 QA 合入 `0a480df`、`ab44f09`，交件文件至 `44efc7b`。中性文字與 AI 再驗的交互問題已通過實際 Live。
- 引用／hash／CLI 字面來源核對不放寬；錯誤記錄保留，最多一次引用修正仍受原預算限制。SIMULATED 的故障注入不列作正式 Live 成功。
- **待完成的是正式網頁串起工程、補件重判與 Live／報告。** 合回 main 的 `871eb7b` 已通過 GitHub CI 34677290816：116 passed、23 subtests、schema 重產一致。本機預設 pytest 曾誤收集 var/parallel 內其他 checkout；本輪補 `testpaths = tests`，只收本 checkout，修正後本機亦為 116 passed、23 subtests，35.46 秒。正式 UI 仍未宣稱完成。

## 第二輪首筆接線與 Live 風險

- D 固定 renderer `40802c8`、report `184145c` 的真 ROM JSON 呈現通過，AI 身分欄位完整。指定整合 `a47a1a3` 尚缺 analyze／正式分析保存；新 `codex/integration-offline` 的 `70b3b68` 已交 `Runner.analyze_offline`／`read_engineering` 與固定 OFFLINE worker，並記錄真實 ROM／CMake／curl 五 query 的保存驗收；UI 接線及 Live 仍待完成。該版核心基於 `0a480df`，請再接 PR #9 以取得 A/B 修正，不能把舊基線發現套到新版本。
- 上述 renderer/report 只顯示 witnesses，未呈現核心既有 `evidence.excerpts` 的 X-ID、行號、原文與 hash；請 Frankie 接上既有內容及同 scope 的來源操作，不自造 locator。
- B 的 ROM 補件後 Live 第一筆用盡 8 次呼叫（73.196 秒）仍未 COMPLETE，含一次 COMPARE 四來源的 TOOL_ERROR；工程 dict／已保存 JSON 保留，AI 失敗後未重判。這筆保留為 BUDGET_EXHAUSTED，不能被早先 Live 成功數掩蓋；需評估工具參數引導與剩餘預算收尾。B 第二筆聚焦正常 TCP/TLS 的 Live 已通過（2 calls、16.519 秒），正式歷史／工程保留。主線再針對第一筆原問題修正預算提示與工具參數引導；`dd47a1e` 真實 Live 已由 8 次耗盡改為 5 次完成、44.872 秒，8 筆新原文重核並維持 Not Affected。原失敗保留，不放寬 Verifier／不增加預算；一次結果不能當成功率保證。

## 並行工作與接收

使用者已授權最多主線以外三個活躍獨立工作。第一輪 A/B/C 已整合；側邊協調者已續派 B 合併後 Live、C 合併後回歸，另開 D 核心與前端 JSON 驗收，均固定產品 `44efc7b`，只改各自 QA／報告，不改產品或 Frankie 檔案。主線不重複跑三項，也不等待全部 QA 才交接線 checkpoint。第二輪工作區如下，SHA 與結論從各自同步文件收取。

| 第二輪 | 對話／範圍 | Fresh 下工作區／分支 |
|---|---|---|
| B Live | 沿用 B 對話；ROM 補件及歷史文字後 Live、失敗保留 | `var/parallel/ai-validation-r2`／`codex/parallel-ai-validation-r2` |
| C 回歸 | 沿用 C 對話；ROM 真 archive／補件／文字與錯誤，不打 API | `var/parallel/qa-r2`／`codex/parallel-qa-r2` |
| D 介面 | `01a09435-fce5-75c3-8fa9-c0ba82299c99`；JSON → renderer／report／Runner mapping | `var/parallel/contract-qa`／`codex/parallel-contract-qa` |

| 第一輪 | 對話 ID | 分支／Fresh 下工作區 |
|---|---|---|
| A 語意 | `01a0941e-c2fd-7012-a333-c69f25df96e2` | `codex/parallel-semantics`／`var/parallel/semantics` |
| B AI | `01a0941f-2066-7d30-9d24-2e72b2fde2d7` | `codex/parallel-ai-reliability`／`var/parallel/ai-reliability` |
| C QA | `01a0941f-78ba-78b2-8ce3-5c8624cdb2c7` | `codex/parallel-qa`／`var/parallel/qa` |

此工具環境無跨對話讀取／發訊工具，以 worktree 同步 MD 與 Git commit 收件；不要求使用者搬運結果。heartbeat `cvevidence` 每五分鐘補巡檢，今日 17:35 截止；完成／叫停後停用。15:35 後新派工集中展示阻塞、接線、驗收與排練。

## 存放與提交

展示輸入 `demo-inputs/` 已入 Git；原 build/archive 在 `var/artifacts/`，本機 run 在 `var/runtime/`，報告在 `var/exports/`，可公開驗收摘要在 `docs/releases/`。不提交客戶原始資料、key 或完整模型私有推理。每輪取得遠端最新狀態，只 stage 本人改動；不 force push，由整合負責人審查後合 main。

## 本輪新交件

- B 第二輪 QA 已合入 `848cb32`／`c1d0604`／`7853ed3`，C 第二輪已合入 `19a8b78`／`65789d2`。C 16 項通過、無新產品 blocker；B 2 模擬通過、兩筆原 Live 一通過一失敗。原始固定基準為 `44efc7b`，不改寫成新 head 已全數重跑。
- 核心 `analyses[].condition_groups` 提供 PC1／PC2／PC3 與共用前提，僅供呈現；assessment／Evidence ID 與判定規則不變。Frankie 可依欄位顯示，不用猜 PC 分組。
- 新 Live 保存 started_at／finished_at；Replay 帶原時間與本次播放時間。舊紀錄缺時間明示未知，不補造。
- 以上對應 V5 PC 條件分組、Replay 帶原時間、追加補件含取證角色與驗收材料；詳細字段見核心接線提案。

本輪產品與 main 相容測試：119 passed、23 subtests，29.86 秒；另 49 項 AI／回流聚焦測試通過。新增使用者未交付入口的 Live／Replay 驗收腳本，待實際結果另記，不預填通過。

## 14:25 接收 main 與補齊驗收

- main 已到 `9d11d48`（PR #13），含正式 OFFLINE 工程工作台與補件／報告。已合回作者分支處理 README 衝突；main 的 Frankie 產品檔原樣保留，新的相容測試執行中。
- 程式 `7479368`：使用者指出尚未交付的網路 gzip 入口，真實 Sol／medium 4 calls、36.449 秒 → ASK_USER／NEEDS_USER_INPUT；原已驗條件不變，整體 NEEDS_INVESTIGATION。補件列成品、source、build/link 和啟動材料，角色與核對目的在 finding；漏洞重現不是必要補件。一筆 S-ID 引用被拒並在原預算內修正，失敗紀錄保留。Live／Replay 原時間均核對通過。
- 補齊 PC 分組與 Replay 時間的 `9f3ac28` 已用 pip 打包安裝；在 repo 外載入 site-packages，reviewed_sources.json 與 PC metadata 皆可用。後續 `7479368` 僅多一行最小補件提示。
- D 指定版本的 QA 報告與重現程式已推分支 `codex/parallel-contract-qa`，固定交件 `754e6a3`。基本 JSON／錯誤隔離通過，原文 excerpts 顯示有兩個已知失敗；其舊 integration a47a1a3 的未接線狀態已被 main 新 OFFLINE 接線更新，不能沿用作最新結果。D 的測試針對固定舊 consumer，未合進預設最新產品測試以混算成效。
