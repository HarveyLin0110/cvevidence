# 整合 session 同步
更新：2026-09-12。使用者已決定本 session 專注整合，Frankie 新功能在另一 session 開發。

## 工作邊界
- 本分支：codex/integration-handoff。
- 本機工作目錄：~/projects/cvevidence-integration。
- Frankie 個人開發分支已確認：codex/frankie-feature-development；目錄 ~/projects/cvevidence-fresh，port8506。本整合目錄使用port8505，双方不操作對方服務。
- 本 session 只做雙方 commit 接入、介面相容修正、整合測試、服務驗證與交接；不另寫 Query/判定/AI，也不擴寫多 CVE 或其他前端新功能。
- 新功能交付請附分支/SHA、介面樣例、測試與變更範圍；使用者2026-09-12已授權整合端按 docs/integration/plan.md 門檻審查後主動透過PR合入main，不重問相同授權、不繞過保護。
- 全部整合任務I00–I15與每15分鐘巡檢見 docs/integration/plan.md；本機heartbeat cvevidence-main已啟用。
- Horace.md 僅由 Horace 維護；本 session 後續更新此檔，避免與另一個 Frankie 開發 session 同改 Frankie.md。

## 最新整合更新：2026-09-12 14:58

以下舊里程碑段落保留歷史；以本段及 docs/releases/integrated-ai-20260912.md 為最新接線狀態。
main e9cc996 已發布 OFFLINE 工程／補件／報告與產品 UI。codex/integration-ai-release 已合 Horace9863b1b、Frankie c8c1128，並呈現 PC 分組與原文段落。
合併程式 c278130 真實 Sol/medium LIVE：5 calls、34.365秒、NEEDS_USER_INPUT；保存後讀取／報告／補件重判AFFECTED及原紀錄不變均驗收。公開站仍須通過目標 CI／部署／瀏覽器驗收，結果補 PR，不混同本機測試。
I04–I07/I10/I11 的主要工作台路徑已接；I08/I09 正完成 LIVE 發布驗收，Replay UI、取消、總額度控制未完成；I14 Google多人隔離／公開固定版已運行。I12/I13/I15 仍需範圍化最終驗收，不宣稱全部結案。

## 本次接收與結果
- Frankie 基線 44dc613：51項整合基礎測試＋3項服務恢復／歷史容錯測試。
- Horace b71926f：Git 提供 demo-inputs 的9初始＋3補件，以及 repo_path catalog；完整分析核心仍未交付。
- 接入 archive.repo_path，允許來源只在 repo/demo-inputs 或 var/artifacts；目前正式 selected_datasets 排在樣品選單前方。
- 補件也驗 catalog archive/manifest hash；不同 build 由 Horace validate_supplement 拒收。
- 12/12 SHA256SUMS 成功；三格式9/9初始收件、3/3同build補件成功，四種來源工具與報告成功。
- ROM 432→4294，CMake 260→409，curl 6245→6250；均無覆寫父紀錄、無移除/變更舊來源，錯build拒收。
- 詳細摘要在 docs/releases/official-input-integration-20260912.json。
- 整合PR：https://github.com/HarveyLin0110/cvevidence/pull/3；程式commit 1ac9d4b，56項測試通過，CI34675527610成功。
- 8505實際瀏覽器已通過正式03_rom匯入→資料確認，無舊模型ValidationError。Horace PR#2交接留言已更新正式包收件結果。
- Horace 所述 Sol/medium 與一次 CMake Live 成功是對方的本機進度；此整合版工程/AI仍NOT_RUN。

## 已解決的頁面問題
原8505程序使用舊Python模型，讀sources/DELTA的新紀錄時ValidationError。44dc613已新增重啟管理、程式指紋防護與歷史容錯。
啟動命令：用venv的python執行 scripts/workspace_service.py start/restart/status。code變更後必須restart，再核對瀏覽器；health=ok不能代替畫面驗收。

## 下一個整合關卡
等 Horace 正式交付 collect_evidence / verify / assess / investigate 回應與新 tests，再與 Frankie 前端/Runner新功能合入本分支。
需確認 condition SUPPORTED/BLOCKED/UNKNOWN/衝突、InvestigationTask、工程與AI獨立status、mode/deadline與引用scope；不以模擬或空結果宣稱完成。
