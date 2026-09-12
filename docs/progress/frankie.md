# Frankie 里程碑與實際進度
更新：2026-09-12；正式分支 codex/frankie-fresh-milestones。
使用者確認今日重製；今天的模擬網頁可納管。舊基線上的草擬 commits 保留本機，不推到此分支。
每個里程碑分開 commit，commit SHA 由 git log -- docs/progress/frankie.md 查閱。

| 里程碑 | 範圍 | 狀態 |
| --- | --- | --- |
| M0 | 今日 UI、Git 規則、同步入口 | 完成 |
| M1 | 新共用契約／schema | 待本分支驗證 |
| M2 | Runner／不可變保存／CLI／核心 adapter 邊界 | 待本分支驗證 |
| M3 | 補件／報告／比較 | 待本分支驗證 |
| M4 | 本機 Streamlit／受控來源／整合測試 | 待本分支驗證 |
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
