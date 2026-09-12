# Frankie 開發同步
更新：2026-09-12。此檔只由 Frankie 維護，不修改 Horace.md。

## 已對齊
- 已讀 Horace main 基線 780dac1 的同步文件。
- 使用者確認今日重製；今天製作的模擬網頁例外允許納管。
- 不提交舊登入／core／測試或舊 Demo；原本基於舊 checkout 的 commits 僅留本機。
- Frankie 負責 Runner、contracts、UI/CLI、保存、補件與報告；不另寫 AI planner／Query／Verifier／規則。

## 進度與交接
- 今日新寫模組正逐里程碑在 codex/frankie-fresh-milestones 提交。
- 介面仍為提案；等待 Horace 的真實核心 commit。
- 正式介面以 Python/Streamlit；apps/web 只保存今日 UI 模擬，不要求 Horace 寫 HTTP API。
- Frankie 對外提供 run_analysis／save_supplement 別名，以及既有 start／supplement 方法。
- adapter 邊界需要把 Horace ingest_package 等結果轉為 RunEnvelope 所需資料。未接入時 CORE_UNAVAILABLE，不猜判定。
- InputPackage 的真實 provenance／逐條條件語意需 Horace 校準；Legacy format 不作為正式來源。
- 初版 CLI/UI 要求指定 CVE；無 CVE、多 CVE 候選流程等待 discover_candidates，不自動套 Heartbleed。
- OFFLINE/LIVE 接入與 REPLAY 語意需雙方確認；未設定模型或 key 不能宣稱 Live 成功。
- 執行資料 var/runtime、報告下載來自固定 run；大工程包不進 Git。
- 看 docs/progress/frankie.md 取得每個里程碑驗證結果。沒有即時背景自動更新，於 commit/push 更新。

## M0–M4 已交分支
- M0 dd54b81；M1 360f6c9；M2 430cc70；M3 cb9bbd0；M4 由本次 commit 查閱。
- 全部今日新測試 27 passed；不包括舊環境測試，不代表真實漏洞驗收。
- 接線具體提案：contracts/adapter-handoff.md。
- 此分支預設不提供解析器；CoreAdapter 未設定時保存 CORE_UNAVAILABLE。請提供核心 commit 後再接 M5。
- 下一步：先確認 adapter 的 package reference、證據定位與各階段回應，再做 ROM 真實補件閉環。

## 遠端交付與驗證
- Draft PR：https://github.com/HarveyLin0110/cvevidence/pull/1（尚未合併 main，請由此分支查看最新接線資料）。
- M4 commit：49ddbeb；整理紀錄 d585826。
- GitHub Actions 34673493112 在 d585826 成功：乾淨安裝、新測試、schema 再產生一致性皆通過。
- 本機 Streamlit 已於 127.0.0.1:8505 啟動，health=ok；不公開資料服務。
- 明確待辦：M5 真實核心接線、無 CVE 探索、多 CVE 子 run、完整來源 catalog、實際 Query/規則/AI/九格、多人授權。
- 原本 apps/web 的公開網址仍是模擬介面，不會突然改成暴露本機資料的正式服務。

## AI 安全與亮點統整
- 新增 docs/ai/README.md、developer-guide.md、acceptance.md；README／AGENTS 已連結。
- 分開開發時 AI 與產品內 AI；D01–D10、R01–R12 與 A01–A16 可供 PR／驗收引用。
- 核對 OpenAI 官方 AGENTS.md／agent safety 及 Anthropic AI-native SDLC；不把官方建議當本系統安全認證。
- 修正舊主線：ROM 03→02，補件後需由有效阻斷支持 Not Affected；舊程式／登入檢查不列今日成果。
- 明確列出現有契約／Runner 測試證據，以及 LIVE、語意引用、provenance、隔離及多人授權缺口。
- 不改 Horace 核心或同步文件；指南供共同採用，介面未定部分仍標提案。

## M5a 最新回覆 Horace f577854（取代前述未接核心的歷史狀態）
- 已合入第一輪核心，merge 9e3e17a；未修改 Horace 核心與同步檔。
- ingest/discover/list/search/excerpt/compare/validate_supplement/interpret_statement 已接入 Runner.start_file/source_tool/supplement_file，Web/CLI 共用。
- file-backed 最大512 MiB，真實 product/format/context_hash，sources 與 facts 分開；delta 建立新 archive/context/run，保留 parent；工程/AI 各自 NOT_RUN。
- questions 放寬至100；InvestigationTask 及 SUPPORTED/BLOCKED/衝突仍待共同定義，沒有另寫 Query/規則。
- 原交付包未有 download_url；使用 Horace 今日 builder 新建 frankie-cmake-integration-20260912，並非冒稱取得原 binary。三包收件、06 補件260→409、四種來源工具／報告／錯build拒收成功。
- 本機51項測試通過；詳細驗收及限制：docs/releases/Frankie-core-integration-20260912.md。
- 仍等待 Q1–Q5/Verifier/assess/investigate，以及原 ROM/cmake/curl artifact 交付；M5b/M6 未完成。

## M5a.1 服務恢復與歷史容錯
- 使用者回報8505錯誤；實際瀏覽器確認服務仍載舊Pydantic模型，讀新sources/DELTA紀錄時崩潰。已重啟並確認新版頁面正常。
- 新增程式指紋防護，程式改動後要求重啟，不混用快取模型；scripts/workspace_service.py提供start/restart/stop/status。
- 單筆壞紀錄可見地排除歷史列表，直接讀取仍嚴格拒絕，原檔保留。不存在的已選run可以恢復。
- 54項測試通過；接續多CVE／情境入口、操作追蹤與ROM/curl實包整合驗收，沒有另寫Horace判定／AI。

## F12 個人功能分支交付（2026-09-12）
- session已與整合端分開；我使用codex/frankie-feature-development／8506，整合端8505。
- Runner.submit_request/read_request＋獨立RequestSpec/Result，支援情境DRAFT、多CVE獨立run、固定archive、UUID去重、並發鎖與中斷後禁止模糊重跑。
- UI/CLI共用、草稿延續／請求歷史／JSON下載完成；不修改RunEnvelope或core_service/core_worker/catalog。
- 63測試通過，Horace真實06包兩CVE各260來源驗收通過，瀏覽器DRAFT確認成功。詳見docs/development/F12-request-workflow.md。
- 未做自動解鎖／中斷續跑；Q1/AI等依整合端與Horace交付，不冒稱完成。
