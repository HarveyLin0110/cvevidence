# 團隊站 CMake 現象入口與 Live 實測

2026-09-12，Horace 使用已登入的真實 Chrome 操作使用者提供的 HTTPS 團隊站。這是正式 UI／Runner／網站端 OpenAI API；不是 AppTest、mock、Replay 或直接呼叫本機核心的替代證明。

## 固定版本與輸入

- 站點：`https://laptop-5tcfdp5e.tailea98bd.ts.net/`。探索／首次工程時頁面 `c65e9c7`；網站更新後 Live／補件時頁面 `5918858dd61b889055ba82524402c1dd616c901f`。不是單一版本不中斷的壓力測試。
- 今日 Git 輸入：`demo-inputs/cmake/06_cmake.tar.gz` 與 `supplement_06_cmake.tar.gz`；build `cmake-20260912T041957-c54d2c`。舊 Demo 不作輸入。
- 無 CVE、無工程包時描述「客戶匯入更新檔失敗，log 顯示 gzip stream ended before trailer」，先保存草稿，畫面明示尚無工程判定及非 AI 的資料引導。
- 草稿 `8a29dfcb-de85-4fdf-a0b2-6c0952775747`；補上工程包的新請求 `25e7665b-f64c-4967-bf6e-ba12ebaf7fdc`；初始收件 prefix `4181bff8`，260 個來源，CVE-2022-37434 只是候選。

## 網站操作與结果

| 階段 | 識別／實際結果 |
|---|---|
| 五項工程查核 | `0a700c0f-0a94-481d-b7b9-23e3aecf6ec4`；Needs Investigation，4 supported／4 unknown |
| 初始 context | `d31f70a934e757d6b567202547ca1e42d223032185afae46e15ecf1510150a11` |
| 網站 AI | `b4565c59-ee92-492b-93ea-1a22b36e65c3`；建立時間 `2026-09-12T07:16:22.965099+00:00` |
| 模型與狀態 | `gpt-5.6-sol`；5 筆 completed Response，LIVE／NEEDS_USER_INPUT |
| 同 build 補件收件 | `d19a1d2b-852c-4b51-a5a0-4388f7cb103d`；COLLECTED |
| 重新工程判定 | `ca8f3fb8-9949-4640-a148-490270bb0ccb`；Affected 工程初判，8 supported／0 unknown |
| 新 context | `383ff3856c9d720d5f136a7e33b671e83ad8fb6ebcaf318ef0faa25ef3ed7cec` |
| 前後比較 | 顯示原工程 run、兩個 context、NI→Affected；library/product binding、entry_reachable、trigger_prerequisites 四項改變 |

AI 實際先 READ 截短測試日誌與命令紀錄，再 LIST 查詢已提交的 update_reader.c 和 libz.a，最後 ASK_USER。它把正常截短樣本的錯誤訊息與「客戶檔案確實截短」及 CVE 適用性分開；要求客戶實收檔案 hash／大小、官方發布清單，以及同 build 的 libz.a、source、linker map／輸入雜湊。非惡意動態診斷明列可選，不要求漏洞利用重現。

五筆原生 Response 的 total tokens 分別為 3836、4170、4769、5014、6152。這是此一次調查的紀錄，不推估成功率、成本或全站預算。UI 模型欄未顯示 reasoning effort，本紀錄不單靠頁面宣稱 medium 已核對。

原工程＋AI 完整文字報告已經由 UI 讀取保存，含正確 run／AI ID 與 LIVE。完成補件後重新開啟網站，從歷史載入原工程：原 AI ID／LIVE／追問仍在，13,590 字元的原報告逐字相同，未混入新工程 run；沒有再次按下 AI 調查。完整可見頁面與報告保留 Fresh 忽略目录 `var/validation/team-site-cmake-5918858/`；不把原始執行材料或金鑰送進 Git。

## 限制與後續接線

1. 原本本機 `.env.local` 不會隨 Git 傳送。這次網站已有自己服務端可信配置，且真實成功呼叫；畫面的 OFFLINE 是工程那一階段未呼叫模型，不表示網站 API 永遠未接線。
2. 測試間兩次短暫 Connecting，頁面部署版本也改變；原工程在更新後可從保存歷史重新載入。沒有由 Horace 重啟／部署服務，不能稱受控服務重啟驗收。
3. 補件後原現象欄位空白；另有 NOTE→DELTA 丟失歷史文字的真 Runner 重現。修正另在 `codex/horace-integration-history`，見 [歷史接線修正](Runner_補件歷史接線修正_2026-09-12.md)，本次網站還未套用。
4. 本次沿用當時三 profile 的工程定義；新的 PC3 實際部署／運作材料與 Query 演進規劃另由側邊工作實作。這次 Affected 仍限定交付成品，不表示客戶環境確已暴露或異常由 CVE 造成。
5. 本次沒有驗證 AI 紀錄下載落地；真實可見的保存紀錄、模型 Response、報告與前後比較已核對。ROM 前輪的第二次下載逾時亦未被本次結果取代。
