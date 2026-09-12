# Horace 開發同步

更新：2026-09-12 13:41（Asia/Taipei）

此檔由 Horace 的工作對話維護，供 Frankie 及其 Codex 讀取。每次形成決定、變更介面或交件後更新；只留影響協作的摘要，不保存完整聊天。Frankie 請自行維護 `docs/sync/Frankie.md`；雙方先讀對方最新內容再動共用介面，避免重做。

## 已確認的限制

- 比賽當日團隊程式、builder、測試及 demo 資料全部重新製作。舊 Demo_3x3、舊程式及驗收結果不複製、不執行；舊 DOCX 僅供需求與概念參考。
- 公開 OSS 今日從官方重新取得，保存版本、URL、授權及 SHA-256。
- 分工以「CVEvidence 工具架構與雙人分工確認 Frankie」DOCX 為準。V5 plan 的較早分工若不一致，由這份分工更新覆蓋；產品與 demo 情境仍參考 V5。
- 模型使用 OpenAI API；使用者已選 `gpt-5.6-sol` / `medium`，真實呼叫成功。key 放環境變數或 Git 忽略的 `.env.local`。金鑰、客戶原始資料不進 Git；使用者要求今天重建的 demo 輸入納入 Git，已新增 `demo-inputs/`。
- 給隊友看的文件盡量用繁體中文；程式識別字與必要技術名詞保留原文。
- 判定為工程初判，待工程師覆核；不能將正常功能測試、版本命中或 AI 意見當完整適用性證明。

## 責任邊界

| Horace 製作 | Frankie 製作 |
|---|---|
| 三種新 builder、真實觀測、九包及補件、驗收比對器 | 樣品/ZIP 操作入口、實測表呈現 |
| 匯入解析、檔案與成品核對、Q1–Q5、原文工具、Verifier | Runner 串接、進度、證據檢視 |
| 三個 CVE profile、候選匹配、判定引擎、Claim 查核、缺口 | 結果與條件呈現、摘要組裝/下載 |
| OpenAI 呼叫、AI 追加問題與工具調查、引用核對、補件指引 | 模式操作、整次逾時、UI 錯誤處理 |
| 同 build 補件驗證、文字聲明語意、矛盾提示 | 保存、不可變快照、parent run、歷史與前後比較 |
| 分析欄位與語意提案、可獨立驗收的小型 CLI | 共用 contracts 主維護、正式 Web/CLI 共用 Runner |

Horace 的開發 CLI 僅供核心驗收，不另做正式 Runner、Web 或保存系統。Frankie 不需再寫另一套 AI planner、query、Verifier 或判定規則。

## 產品及 demo 對齊

- 兩入口：先描述現象（允許初始無檔案、無 CVE），或指定一至多個 CVE；候選 ≠ 產品適用性 ≠ 異常原因。
- 先跑 Q1_COMPONENT、Q2_BUILD、Q3_IMPLEMENTATION、Q4_BINDING、Q5_PATH，再讓 AI 依當次內容提出新的調查問題、使用唯讀工具或要求補件。新增問題不固定為 Q6。
- 三種實際交付：ROM/SquashFS＋SDK；CMake 靜態 zlib；curl 安裝＋launcher/config。
- 完整目標六個新 build、九個初始包、三組同 build 補件。03 來自 ROM 02，補回同次資料後有效阻斷才 Not Affected；06 來自 CMake 04、09 來自 curl 07，完整條件成立才 Affected。
- build 完成、工程判定通過、Live AI 通過分開統計，不預填九格結果。
- 分析器只讀當次匯入資料，不執行匯入 binary，不讀 factory/測試答案/其他樣品/未交補件。

## 介面狀態

**已讀 Frankie 分支 364a657 的 M5a 同步：已整合第一輪核心、file-backed 收件、來源操作與同 build delta 補件。下面分析階段擴充仍為提案。**

- Python 可匯入核心，由 Frankie 的 Runner/Streamlit 呼叫；回傳可 JSON 化物件。
- 物件：InputPackage（可讀來源/manifest/context）、EvidenceRecord、AIProposal/InvestigationTask、Supplement、Assessment、RunEnvelope。
- 入口：`ingest_package`、`discover_candidates`、`collect_evidence`、`list_sources`、`search_sources`、`read_excerpt`、`compare_sources`、`verify`、`assess`、`investigate`、`validate_supplement`。
- Frankie 擁有 `run_analysis`、`save_supplement`、run ID/parent run/context 保存及前後比較。
- 五項 query 的成功/缺件與正式 verdict 分開；完整性失敗 `assessment=null`；未知 CVE 不套別的 profile。
- OpenAI key 用 `OPENAI_API_KEY`，模型用 `OPENAI_MODEL`；Live/Offline/Replay 分開。尚未設定模型或金鑰不能標 Live 成功。
- Evidence ID 決定於來源/事實/locator，不用 package 顯示名稱決定判定。所有引用須能核對原值與 hash。

## 當前接線 checkpoint

**完整核心 checkpoint：`cb257c3`，已推送 `codex/horace-fresh-core`。Frankie 可先接這版，不需等待額外變體。** 接線入口與範例見 `docs/architecture/核心分析介面與接線提案.md`；Git 输入包為 `demo-inputs/`。

側邊對話正在建立獨立工作區：A 修正中性聲明/矛盾語意（assessment/supplements），B 改善 AI 工具/引用恢復（ai），C 獨立驗收。主線自 checkpoint 起暫停修改 A/B 檔案，保留 Query/Verifier/workflow/adapter/CLI 與最終整合，不重複建立任務。

已知待修：目前所有新文字聲明都會保守退為 Needs Investigation，包括中性「已提供檔案」；A 將校正。當前主線順序：Frankie 第一筆網頁真實結果 → ROM 補件重判 → Live AI → 收取 A/B/C commit 做範圍整合。

## 獨立工作區與接收方式

三個新對話已由側邊協調者建立，基準同為 `b89059fdd1f751b43559187fd488844c9eeb3336`（包含核心 `cb257c3`）。不再重複建立任務；各工作區不改主線 checkout、不合入 main、不改 Horace.md/Frankie.md。

| 任務 | 對話 ID | 分支 | 工作區（相對 Fresh 根目錄） | 獨占檔案 |
|---|---|---|---|---|
| A 判定語意 | `01a0941e-c2fd-7012-a333-c69f25df96e2` | `codex/parallel-semantics` | `var/parallel/semantics` | assessment.py、必要時 supplements.py；自己的測試與 Parallel_Semantics.md |
| B AI 可靠性 | `01a0941f-2066-7d30-9d24-2e72b2fde2d7` | `codex/parallel-ai-reliability` | `var/parallel/ai-reliability` | ai.py；自己的測試／驗收脚本與 Parallel_AI.md |
| C 獨立驗收 | `01a0941f-78ba-78b2-8ce3-5c8624cdb2c7` | `codex/parallel-qa` | `var/parallel/qa` | scripts/qa_parallel、tests/qa_parallel、Parallel_QA 報告與同步 |

新交件以對話通知、各自同步 MD 與 Git commit 收取，依 diff 範圍由 Horace 整合；C 只補驗新變更，不重跑既有大批測試。原環境的 API key 不複製到這些工作區。

主線補充 `7535246`：`workflow.investigate_after_engineering(context, saved_result, ...)` 讓網頁先保存、顯示工程結果，再啟動 Live；AI 設定不足／逾時不改動原工程 dict。新增一項失敗保留測試，主線現為 32 項通過。這個改動不涉及 A/B 獨占檔案。

整合注意：B 的 AI 入站會重核 assessment 的 verdict／conditions；A 修改 statement_reviews 語意時，需一併確認 B 不再把任何中性 review 都推成 Needs Investigation。AI 新增原文只能先算 exact excerpt，升級工程條件必須經 profile 確定性提取與 Verifier，不採模型自由結論。

## 目前有證據的進度

- 九格工程判定 9/9、三條同 build 補件重判 3/3；完整結果與條件見 `docs/releases/Horace_完整核心與Demo交件.md` 及 `docs/releases/驗收證據/`。
- Q1–Q5、source/object/archive/shared/product 綁定、ROM 真實 image 解析、Verifier 重取證、三個 profile、Claim、補件聲明語意與中文摘要已提供。
- 31 項核心邊界測試通過；乾淨 venv 安裝與 package data 載入通過。真包篡改 source、多一個 ELF、build 衝突皆轉 Needs Investigation。
- ROM 03、CMake 04、curl 09 各 10 次 OFFLINE，共 30 次，verdict / Assessment ID / Evidence ID 穩定。
- Sol/medium 四情境 Live 調查通過：ROM 缺件、CMake 症狀、curl 缺件、curl 提前提供材料。AI 時間約 28–55 秒，不能當固定延遲保證。
- 一筆 Live 不存在 X-ID 已拒絕並保留失敗紀錄；現在預算內可修正一次引用/hash，REJECTED 不隱藏。AI 引用精確核對 ≠ 語意證明，工程判定仍由規則負責。
- 目前資料選 ROM r2、CMake r2、curl r2。curl r2 已補齊 libtool compiler header capture，兩版重新建置並完成 archive/補件資料驗收。

## 交件與存放

第一輪程式 commit：`f1d49f4`；分支 `codex/horace-fresh-core`；[Draft PR #2](https://github.com/HarveyLin0110/cvevidence/pull/2)。交件詳見該分支的 `docs/releases/Horace_第一輪資料與核心交件.md`：含已可呼叫的匯入/唯讀/補件介面、命令、真實驗收及限制。完整核心已實作並通過上述驗收；請以本分支最新版本接 `analyze_archive_for_runner`，介面詳見 `docs/architecture/核心分析介面與接線提案.md`。

- 程式：`src/cvevidence_core/`；builder：`tools/demo-data/factory/`；格式：`contracts/`。
- 新交件 commit `8882c75`：Git 的 `demo-inputs/` 含 9 初始包＋3 補件，約 95 MB，最大 17 MB；附中文上傳對照表、catalog、SHA256SUMS。請整合此 commit，無需再自行重建原展示包。
- `data/catalogs/` 新增 `archive.repo_path` 指向 Git 輸入；原 build/archive 本機歷史保留於 `var/artifacts/`。前端選檔器需接受 `.tar.gz`（核心已支援）。
- 當次結果：`var/runtime/runs/<run_id>/`，包括 queries/evidence/conditions/assessment/AI 工作與事件。
- 報告：`var/exports/reports/<run_id>/`；可公開的測試摘要：`docs/releases/`。
- 唯一開發與 Git 根目錄為 `CVEvidence_Fresh_2026-09-12`。Git 歷史已從參考目錄移入；Frankie 用 repo 相對路徑。舊 `CodexHackathon` 僅作概念參考；棄用 `CVEvidence_2026-09-12` 已移至垃圾桶。

## 請 Frankie 在自己的同步檔回覆

1. 已讀到 Frankie 確認責任及 Python/Streamlit；為避免檔名撞到 Frankie 的 sources.py/cli.py，Horace 核心改為獨立 `src/cvevidence_core/`，開發 CLI 用 `python -m cvevidence_core`。
2. 原 v0.2 collect/read 保持相容。新增 file-backed `analyze_archive_for_runner(archive_path, options, expected_archive_sha256=..., expected_context_hash=..., temporary_root=..., env_file=...)`；真實 Git CMake archive 已跑完整 Q1–Q5/verify/assess，409 sources、Affected、AI OFFLINE。亦可在 M5a worker 解包後直接 `analyze_package(context, ...)`。
3. 已讀 M5a 的 file-backed 512 MiB、source/fact 分離、獨立工程/AI 狀態、delta/context 接入。下一步只需對齊 condition 的 SUPPORTED/BLOCKED/UNKNOWN/衝突、動態 InvestigationTask 與分析階段；Horace 不修改 Frankie 的 contracts/Runner。

完整分析 contracts 映射仍為提案，不擅自宣告 Frankie 已接完。M5a intake worker 不傳金鑰；Live 接線須由可信任的 AI 執行程序取得 OpenAI 設定，並獨立呈現 AI 狀態。

## 更新方式

每輪只更新有變動的現況，舊事項完成後移除待辦；保留影響接線的決定及真實失敗摘要。推送前先取得遠端最新狀態，只提交自己的同步檔，不覆蓋對方檔案，不 force push。新介面先標「提案」，雙方回覆後才標「已定」。
