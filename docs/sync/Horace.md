# Horace 開發同步

更新：2026-09-12 12:42（Asia/Taipei）

此檔由 Horace 的工作對話維護，供 Frankie 及其 Codex 讀取。每次形成決定、變更介面或交件後更新；只留影響協作的摘要，不保存完整聊天。Frankie 請自行維護 `docs/sync/Frankie.md`；雙方先讀對方最新內容再動共用介面，避免重做。

## 已確認的限制

- 比賽當日團隊程式、builder、測試及 demo 資料全部重新製作。舊 Demo_3x3、舊程式及驗收結果不複製、不執行；舊 DOCX 僅供需求與概念參考。
- 公開 OSS 今日從官方重新取得，保存版本、URL、授權及 SHA-256。
- 分工以「CVEvidence 工具架構與雙人分工確認 Frankie」DOCX 為準。V5 plan 的較早分工若不一致，由這份分工更新覆蓋；產品與 demo 情境仍參考 V5。
- 模型使用 OpenAI API；key 放 `OPENAI_API_KEY` 環境變數。金鑰、客戶原始資料及完整工程包不進 Git。
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

**已讀 Frankie 分支 a5f9e65 的同步及 adapter 提案；下面未共同確認的擴充仍為提案。**

- Python 可匯入核心，由 Frankie 的 Runner/Streamlit 呼叫；回傳可 JSON 化物件。
- 物件：InputPackage（可讀來源/manifest/context）、EvidenceRecord、AIProposal/InvestigationTask、Supplement、Assessment、RunEnvelope。
- 入口：`ingest_package`、`discover_candidates`、`collect_evidence`、`list_sources`、`search_sources`、`read_excerpt`、`compare_sources`、`verify`、`assess`、`investigate`、`validate_supplement`。
- Frankie 擁有 `run_analysis`、`save_supplement`、run ID/parent run/context 保存及前後比較。
- 五項 query 的成功/缺件與正式 verdict 分開；完整性失敗 `assessment=null`；未知 CVE 不套別的 profile。
- OpenAI key 用 `OPENAI_API_KEY`，模型用 `OPENAI_MODEL`；Live/Offline/Replay 分開。尚未設定模型或金鑰不能標 Live 成功。
- Evidence ID 決定於來源/事實/locator，不用 package 顯示名稱決定判定。所有引用須能核對原值與 hash。

## 目前有證據的進度

- 六個 build、九個初始包、三組補件已完成。第一輪九包資料驗收 9/9、同 build 補件 3/3；正式工程與 Live AI 尚未驗收。
- 匯入/來源清單/搜尋/原文/比較/補件驗證/候選初版已可獨立呼叫；15 項邊界測試通過。
- ROM 正在增加真實 localhost TCP 服務入口並重新建置。舊版 socketpair 正常測試已過，新版要另外驗收。
- curl 官方 patch 的產品程式 hunk 已成功套用；上游測試清單的 context 與 8.3.0 不同，保留失敗紀錄，精確提取官方 `lib/socks.c` hunk 重建後正常下載通過。
- 未完成：Q1–Q5/正式 Verifier、規則與 Claim、AI、工程九格、Live AI。
- API 設定：使用者會設定 OPENAI_API_KEY / OPENAI_MODEL，再通知；目前無 Live 成績。

## 交件與存放

第一輪交件詳見 [資料與核心交件](../releases/Horace_第一輪資料與核心交件.md)：含已可呼叫的匯入/唯讀/補件介面、命令、真實驗收及限制。完整分析尚未可用，Frankie 可先接收件與原文操作。

- 程式：`src/cvevidence_core/`；builder：`tools/demo-data/factory/`；格式：`contracts/`。
- 小型資料索引：`data/catalogs/`，含 archive/hash/取得位置；完整包放 artifact storage/本機 `var/artifacts/`。
- 當次結果：`var/runtime/runs/<run_id>/`，包括 queries/evidence/conditions/assessment/AI 工作與事件。
- 報告：`var/exports/reports/<run_id>/`；可公開的測試摘要：`docs/releases/`。
- 唯一開發與 Git 根目錄為 `CVEvidence_Fresh_2026-09-12`。Git 歷史已從參考目錄移入；Frankie 用 repo 相對路徑。舊 `CodexHackathon` 僅作概念參考；棄用 `CVEvidence_2026-09-12` 已移至垃圾桶。

## 請 Frankie 在自己的同步檔回覆

1. 已讀到 Frankie 確認責任及 Python/Streamlit；為避免檔名撞到 Frankie 的 sources.py/cli.py，Horace 核心改為獨立 `src/cvevidence_core/`，開發 CLI 用 `python -m cvevidence_core`。
2. Horace 會提供 `CVEVIDENCE_CORE_MODULE=cvevidence_core.frankie_adapter`，先相容 v0.2 collect/read。這只接真實收件，不把 collect 當完整分析。
3. 請下一版契約加入 file-backed package reference（20 MiB 上限不足部分工程包）、source 與 fact 分開、condition 的 SUPPORTED/BLOCKED/UNKNOWN/衝突語意、動態 InvestigationTask（不限制三問）、獨立工程/AI 狀態、delta 補件合併及 context hash。Horace 不修改 Frankie 的 contracts/Runner。

在收到回覆前，Horace 持續做不受介面差異影響的建置、取證與測試；不擅自宣告雙方已確認。

## 更新方式

每輪只更新有變動的現況，舊事項完成後移除待辦；保留影響接線的決定及真實失敗摘要。推送前先取得遠端最新狀態，只提交自己的同步檔，不覆蓋對方檔案，不 force push。新介面先標「提案」，雙方回覆後才標「已定」。
