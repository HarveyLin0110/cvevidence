# PC3 第二版交件：同成品從靜態證據走到運作驗證

目標為 2026-09-12 16:00 第二版。作者工作樹 codex/pc3-query-evolution；UI 由「PC2 PC3 分層畫面與報告」獨立對話交件，已合入 UI commit 8677b2a 的內容，再整合 main 0e20c6e。主對話的 PR20 歷史保留修正獨立交付，沒有重寫它的接線。

## 人的關鍵判斷、Codex 任務與交付

團隊指出 PC2／PC3 都在看原碼，評審難以理解層次。人決定：PC2 包含建置、功能設定、實作、成品綁定及靜態路徑；PC3 必須是同成品的實際運作材料，可以缺少，也可以要求用戶補件。補件本身會帶出需要驗證的新問題。

交給 Codex 的任務是把此語意同時落入核心、五 Query、動態問題、畫面、報告、今日新 Demo 與驗收，且保留不可變歷史。分開 UI 和核心工作後，由協調者合併並測試真實 Runner 流程；額外唯讀對話檢查重大判定缺口，不擴充需求。

這輪最能展示的貢獻：三種今日真實成品，PC2 初始已齊全，PC3 初始未知；同 build 補件只增加運作資料，核心再驗證、重新判定。原碼、binary 與 PC2 證據保持不變。這是可查核的程式及測試貢獻，沒有聲稱未量測的速度提升或奪冠保證。

## 介面與行為

- Q1_COMPONENT／Q2_BUILD／Q3_IMPLEMENTATION／Q4_BINDING／Q5_PATH ID 保留；每筆新增 title、pc_layer、query_plan_version=2.0。Q1 是 PC1，Q2–Q4 是 PC2，Q5 是 PC3。renderer、結果摘要、報告使用保存的 title，不覆寫舊 run 的五 Query 語意。
- condition_groups schema_version=2.0；既有 entry_reachable／trigger_prerequisites 改歸 PC2，新增正式 runtime_observation 條件。profile_revision 增加 -runtime-v2。PC3 未知阻止 Affected；有可信修補阻斷且範圍完整時仍可 Not Affected，不強迫每案都有 PC3。
- analyses[].followup_queries 保存 DQ-ID、origin=RULE_GAP、question、reason、target_condition_id、required_files、status、evidence_ids、context_hash。等待用戶為 WAITING_USER_INPUT；材料已到、等待其餘材料做內容交叉核對為 WAITING_VERIFICATION；VERIFIED 表示該問題的資料核對完成，仍要看正式條件；REJECTED 是資料驗證失敗，保留更正需求。
- 新增問題 ID 綁定 CVE、build、artifact、材料 path，跨補件保留身分；收據引用新的 log／trace／配置／樣本會產生新問題。相同快照不重複新增；讀到檔案或模型完成工具不等於 CVE 條件成立。
- runtime_observation 摘要有 status、evidence_basis、description、provenance_verified。每個 runtime 事實都走原 collect→verify→assess；追加 Query 與觀測 metadata 同樣納入 verifier 重算，不能直接改 JSON 宣稱驗證成功。
- 既有 AI tasks 顯示 origin=MODEL；ASK_USER 的工具執行完成顯示為等待用戶。原有8次／90秒核心預算及外層逾時不改，失敗保存、無自動暗轉成功。
- 正式 workspace 的 compare_analyses 呼叫已傳 include_followup_queries=True；原函式預設回傳格式保留相容性。新快照顯示問題新增／移除／狀態改變，不推測問題之間的語意關係。

## 收件與展示

首選 CMake，curl／ROM 對照。六包在 demo-inputs/runtime-v2/，catalog、SHA256SUMS 及操作 README 同步交付。data/catalogs/index.json 預設只選 fresh-pc3-runtime-v2，舊資料仍可查閱。資料不含預填 verdict、API key、TLS 私鑰或昨日 Demo。

解析器只核對有界的原始資料與 hash，**不執行上傳命令、binary 或腳本**。三個 profile 分別支持正常 TLS 往返、gzip extra/chunk 處理及 SOCKS5 remote-DNS wire/config。生產 demo 的操作人員腳本僅對今日已完成且核對 hash 的可信任 factory builds 重收正常觀測。

## 版本及誠實限制

- 舊工程 run／AI／報告可以原樣讀取，不自動重判。啟用新版後，舊 profile 的工程結果不直接送新版 Live verifier；需建立新工程分析取得 -runtime-v2，再啟動 AI。遇到不相容應可見失敗，不能混用舊判定与新證據。
- 舊的完整靜態包在新版可能由 Affected 變成 Needs Investigation，因為新要求 PC3；這是明示的規則變更。舊三組補件仍可收件，但不宣稱它們已補足新版運作要求。
- CONTROLLED_LOCAL_OBSERVATION 是今日受控正常觀測，不是實體客戶 FW 來源認證、漏洞利用成功、實際部署暴露或異常根因。Hash 一致支持材料一致性，來源可信度仍需人工覆核。
- 不包含通用 PCAP parser、截圖 OCR、任意 SSH／FW 自動操作或新增 HTTP 層。五個起始 Query 加上有界的規則／模型追加問題，並非無限背景自治代理。

## 驗收記錄

核心第一輪：192 tests、23 subtests 通過；包含三格式真包、同成品補件、receipt-only 追加問題、錯 build／hash／輸出／命令／環境拒絕、Query 篡改 verifier 拒絕。新版六包 SHA256SUMS 全部通過。UI 支線的純呈現驗收與真 CVE 規則驗收分開，不把模擬畫面當真實漏洞驗證。

合併 main 後的完整 pytest、真實 Live、獨立重大缺口覆核及最終精確提交以本文件後續追加及 PR checks 為準。公開站整合／部署由整合對話負責，本分支沒有重啟公開服務。

適用 AI 規則：D01／D02／D06／D09；R01（scope）、R04（動態問題）、R06（文字不升格／正常觀測不等於完整適用性）、R08（LIVE與失敗分開）、R11（新快照／歷史）。測試分別覆蓋 scope/hash、問題演進、假輸出拒收、OFFLINE不呼叫模型、父 run 保留；Live 結果另留可公開摘要，完整本機紀錄不入 Git。

### 真實 Live 與獨立覆核

ca55381 使用新 curl 初始包，正式 Runner → gpt-5.6-sol **5 次真實 API 呼叫 → NEEDS_USER_INPUT**；模型先 LIST 運作材料、READ 已提交 launcher，再要求同成品收據、原始輸出與配置。之後同成品 runtime 補件 → Affected，父工程原檔不變，重新建立 Runner 後原工程及 AI 均可讀。完整流程 217.223 秒，包含 curl 的工程查核及補件重分析，**不是純 API 延遲**。紀錄摘要見驗收證據/PC3_V2_Curl_Live摘要.json。

此 Live 是 ca55381 的具名結果；隨後獨立對話指出的命令／材料綁定、gzip 截斷與 Query 拒絕歸屬問題另已修正並新增回歸測試。修正要求 ROM 精確命令、curl／CMake 命令使用已核對材料 path、gzip 有界完整解壓／CRC／trailer／output_bytes 一致；資料組合未驗證完成前不標 VERIFIED。未將先前 Live 冒稱為每個後續 commit 重新呼叫 API。

合併 main 的第一次完整測試為 212 passed／6 failed（23 subtests）：六個失敗皆為新 UI 支線預期舊 UNKNOWN 中文措辭，而 Frankie 的新結論畫面已改字。採用 main 的較清楚文案並同步該六個測試；沒有放寬判定或刪除未知／作用域測試。最終完整測試結果另追加。

### 收斂與最新主線整合

1ca3834 的完整 pytest **226 passed、23 subtests，144.71 秒**；46 項聚焦案例57.09秒通過，schema重產一致。独立唯讀覆核已確認原三項缺口封住，未見新增重大回歸；该覆核沒有冒稱另跑測試。

15:46 合入最新 main 7cd00e6（含 PR21 的 PC 摘要卡、請求導航及 PR20 歷史修正），解決兩個 UI 檔衝突。保留主線更嚴格的 PC 條件分組核對與摘要卡，接上 v2 Query／運作狀態；不再顯示重複的舊 PC 區塊。既有驗收腳本 validate_demo_workflow.py 改用 runtime-v2，第一個請求如實待查、第二個請求 runtime 補件後再受影響，仍驗證多CVE隔離、報告、請求切換與父紀錄不變。最新整合 head 的完整測試以 PR22 後續 checks 為準。
