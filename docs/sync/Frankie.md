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
