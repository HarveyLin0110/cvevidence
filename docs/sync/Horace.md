# Horace 開發同步

更新：2026-09-12 12:21（Asia/Taipei）

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

**以下為 Horace 提案，尚未收到 Frankie 確認；不可當作已凍結契約。**

- Python 可匯入核心，由 Frankie 的 Runner/Streamlit 呼叫；回傳可 JSON 化物件。
- 物件：InputPackage（可讀來源/manifest/context）、EvidenceRecord、AIProposal/InvestigationTask、Supplement、Assessment、RunEnvelope。
- 入口：`ingest_package`、`discover_candidates`、`collect_evidence`、`list_sources`、`search_sources`、`read_excerpt`、`compare_sources`、`verify`、`assess`、`investigate`、`validate_supplement`。
- Frankie 擁有 `run_analysis`、`save_supplement`、run ID/parent run/context 保存及前後比較。
- 五項 query 的成功/缺件與正式 verdict 分開；完整性失敗 `assessment=null`；未知 CVE 不套別的 profile。
- OpenAI key 用 `OPENAI_API_KEY`，模型用 `OPENAI_MODEL`；Live/Offline/Replay 分開。尚未設定模型或金鑰不能標 Live 成功。
- Evidence ID 決定於來源/事實/locator，不用 package 顯示名稱決定判定。所有引用須能核對原值與 hash。

## 目前有證據的進度

| 項目 | 狀態與證據 |
|---|---|
| 官方 OSS 今日取得 | 已完成五份，下載收據有 hash/URL/時間 |
| 全新 compiler observer、ROM/CMake/curl builder | 初版已寫；仍在真實 build 驗證 |
| 第一個 ROM on build | 已完成真實 OpenSSL build、SquashFS 打包/解包及 hash 比對；解出程式正常 TLS/設定備份還原成功 |
| ROM off、CMake 舊版 | 正在建置；尚未交驗收結果 |
| curl | 第一次 configure 因缺系統 OpenSSL 開發 library 失敗；原始紀錄保留。此情境以 HTTP/SOCKS5 下載驗證，調整為明示不含 TLS 的 build 待重測 |
| 匯入/原文唯讀工具 | 初版已寫，尚未完成真包與邊界測試 |
| Q1–Q5/Verifier/規則/補件/AI/九格 | 尚未完成，不可視為可整合交件 |

## 交件與存放

目前此 commit 只交同步文件；沒有可供 Frankie 執行的核心版本。可整合時會在此明列 commit、執行指令、contracts 版本與已測範圍。

- 程式：`src/cvevidence/`；builder：`tools/demo-data/factory/`；格式：`contracts/`。
- 小型資料索引：`data/catalogs/`，含 archive/hash/取得位置；完整包放 artifact storage/本機 `var/artifacts/`。
- 當次結果：`var/runtime/runs/<run_id>/`，包括 queries/evidence/conditions/assessment/AI 工作與事件。
- 報告：`var/exports/reports/<run_id>/`；可公開的測試摘要：`docs/releases/`。
- Horace 現在的本機開發目錄為 `CVEvidence_Fresh_2026-09-12`；這不是 Frankie 必須存在的路徑，Git 交件後用 repo 相對路徑。

## 請 Frankie 在自己的同步檔回覆

1. 確認上述責任邊界，尤其 AI 調查及判定引擎由 Horace 提供，避免雙寫。
2. 提供已實作 contracts/Runner 的 commit 或欄位範例；若尚未做，可按上述最小提案對齊。
3. 確認目前 UI 是否採分工文件的 Python/Streamlit；若已有其他前端，提供呼叫邊界，不需為此重寫核心。

在收到回覆前，Horace 持續做不受介面差異影響的建置、取證與測試；不擅自宣告雙方已確認。

## 更新方式

每輪只更新有變動的現況，舊事項完成後移除待辦；保留影響接線的決定及真實失敗摘要。推送前先取得遠端最新狀態，只提交自己的同步檔，不覆蓋對方檔案，不 force push。新介面先標「提案」，雙方回覆後才標「已定」。
