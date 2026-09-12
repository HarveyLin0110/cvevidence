# Frankie 里程碑與實際進度
更新：2026-09-12；正式分支 codex/frankie-fresh-milestones。
使用者確認今日重製；今天的模擬網頁可納管。舊基線上的草擬 commits 保留本機，不推到此分支。
每個里程碑分開 commit，commit SHA 由 git log -- docs/progress/frankie.md 查閱。

| 里程碑 | 範圍 | 狀態 |
| --- | --- | --- |
| M0 | 今日 UI、Git 規則、同步入口 | 完成 |
| M1 | 新共用契約／schema | 已完成；詳見下方驗證 |
| M2 | Runner／不可變保存／CLI／核心 adapter 邊界 | 已完成；詳見下方驗證 |
| M3 | 補件／報告／比較 | 已完成；詳見下方驗證 |
| M4 | 本機 Streamlit／受控來源／整合測試 | 已完成；詳見下方驗證 |
| M5 | Horace 真實 ROM 核心閉環 | 等待核心 commit 與真實資料交付 |
| M6 | 三格式／LIVE／九格實測 | 等待 M5；不得預填完成 |

舊環境 43／52／60／66／69 次測試是草擬階段結果，不作為今日乾淨分支驗收。
docs/product/frankie-plan.md 保留此前規劃供參考；實際現況以本檔及 docs/sync/Frankie.md 為準。

## M1 已完成
- 6 種今日新写契約、JSON schema 與 9 個契約測試。
- 乾淨分支 python -m pytest -q：9 passed；沒有執行或複製舊測試。
- M0 dd54b81。契約仍為 proposal，需 Horace 確認語意。

## M2 已完成
- 今日 Runner／隔離 worker／CLI／原子不可變保存已完成。
- 預設 CORE_UNAVAILABLE；只接受操作者配置的核心模組，使用者輸入不能指定模組。
- 未複製舊匯入器，測試使用今天編寫的 TEST_ONLY adapter；不是實際 ZIP／ROM 驗收。
- python -m pytest -q：18 passed。CLI／Runner 一致、timeout、保存失敗、不覆寫與範圍錯誤測試通過。
- M1 commit：360f6c9。

## M3 已完成
- 新補件、父子比較、文字報告與 scoped 原文工具呼叫已實作。
- 未驗文字不改 facts／assessment；替換快照保留既有 bytes 並核對 release／build 宣告。
- 原文由受信任核心模組讀取，Runner 核對 run 引用、size 與 hash，不自行解析真實工程格式。
- python -m pytest -q：24 passed，均為今日合成整合測試。真實材料驗證仍待 Horace。
- M2 commit：430cc70；已推送乾淨分支，沒有推送舊程式歷史。

## M4 已完成
- 本機 Streamlit 接新 Runner，含匯入、保存紀錄載入、缺件、未分析提示、證據、報告與補件。
- 新來源讀取限制在配置 root 內；越界／symlink escape／超大檔拒絕。
- python -m pytest -q：27 passed，含 Streamlit AppTest 頁面切換與補件；不是手動浏览器全流程驗收。
- M3 commit：cb9bbd0。新 GitHub Actions 將自動執行測試與 schema 一致性檢查。
- M5/M6 仍待 Horace 真實核心、資料與 LIVE 回應。

## 遠端交付
- M0–M4 與進度紀錄已 push 至 codex/frankie-fresh-milestones。
- Draft PR #1：https://github.com/HarveyLin0110/cvevidence/pull/1，待協作覆核。
- CI https://github.com/HarveyLin0110/cvevidence/actions/runs/34673493112 在 d585826 成功，含依賴安裝、pytest、schema 一致性。
- 正式分支沒有舊基線祖先，Horace.md 保持原樣；歷史草擬分支只留本機。
- 本機工作台 localhost:8505，預設核心未接入；未進行真實漏洞驗收。

## AI 開發者指南里程碑
- 整理先前安全邊界、SDLC、競賽目標與最新官方資料，新增三份 docs/ai 文件。
- 共 10 項開發規則、12 項 runtime 邊界、16 項驗收情境；已實作／待驗證分開。
- 僅改文件與導覽，不變更 runtime 判定。既有 CI 在 a5f9e65 已通過。

## M5a 真實收件與補件接線（最新；取代上方 M5 等待核心狀態）
- 2026-09-12：合入 Horace f577854，merge 9e3e17a；合併基線42項測試通過。
- 完成 file-backed archive、context/source、候選、原文工具、delta、UI/CLI 共用 Runner。
- 新建真實 CMake 兩個版本，三包收件3/3，06補件260→409，新增149，父run不變，錯build拒收。
- 51項測試通過，另有真實資料驗收腳本與摘要。詳見 ../releases/Frankie-core-integration-20260912.md。
- M5b ROM完整判定閉環與M6三格式/LIVE/九格尚未完成，不把本次收件成果宣稱完整分析。

## M5a.1（2026-09-12）
修復舊服務快取模型造成新版紀錄ValidationError，補程式指紋防護、服務重啟管理、歷史容錯；54項測試通過，實際瀏覽器確認頁面恢復。

## F12：情境與多CVE請求
已完成DRAFT、多CVE独立run、固定archive、重複與並發提交防護、CLI/UI/歷史下載。63測試通過＋真實06包與瀏覽器驗證。接口／限制／範例見../development/F12-request-workflow.md。8506功能端交付後由整合端合入8505，不在此合main。

## F13：手動來源操作追蹤
START/END收據、scope校驗、失敗分類、報告頁與CLI下載完成；68測試通過。基於F12另分支交付，詳見../development/F13-operation-history.md。

## F14b / F14c 個人功能交付（2026-09-12）
- F14 設計 bec5368；唯讀分析與 AI 畫面 40802c8（PR #7）；文字報告與同 build 條件差異 5e7dc24（PR #8）。
- 81 項 pytest 通過；F14b CI 通過。完整交付說明見 docs/development/F14b-renderer-delivery.md 與 F14c-report-delivery.md。
- 不修改 RunEnvelope、worker、workspace 或部署入口；整合端明確確認先做獨立元件，正式保存格式／AI 入口就緒後才接線。
- 真實工作台工程分析、獨立 AI 呼叫、補件後完整分析及正式報告連接尚未驗收；不以 TEST_ONLY UI 案例替代真實 CVE 驗收。

## F15：獨立 AI 工作台（2026-09-12）
新增 AI attempt 保存、可信任 worker、明確外送授權、冪等與並發防護、歷史及報告副本；原工程保持不變。詳見 ../development/F15-ai-workspace.md。真實最小 API 請求成功；CMake06 首次完整 AI 為 TIMED_OUT，保留失敗，不列成功。此 session 負責8506；整合端負責8505/8507及主線發布。

### F15 真實閉環交付
程式25a39bf（f11ca7a + main e9cc996），136測試通過。CMake06第二次獨立Sol/low AI實際2 calls→NEEDS_USER_INPUT，要求同build libz.a；AppTest顯示真實AI／報告、套用補件／重判AFFECTED，原工程與首次TIMED_OUT保持。詳見 docs/releases/Frankie-F15-live-acceptance-20260912.md。PR14已推送；公開部署與新核心升級交整合端。

## F16：統整性結果摘要（2026-09-12）
結果先顯示完整結論/依據/未知原因，再列五Query發現、缺件與矛盾；PC及完整條件表改為折疊。純展示，不改規則或AI。8506真實ROM保存結果瀏覽器核對成功；詳見 docs/development/F16-result-summary.md。待固定SHA交整合發布。

## F17：結論面向與情境（2026-09-12）
新增12種證據情境的結論設計矩陣，分工程適用性／漏洞重現／部署暴露；未有獨立受驗證欄位時不推論重現或暴露。結果頁與報告共用證據邊界，條件SUPPORTED僅支持該主張。核心trigger_prerequisites範圍疑義記待Horace覆核，不改規則。詳見 docs/development/F17-conclusion-scenarios.md。
