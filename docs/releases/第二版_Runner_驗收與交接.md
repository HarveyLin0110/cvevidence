# 第二版 Runner：PC 分層、運作補件與歷史驗收

2026-09-12 15:38，Horace。依使用者要求，16:00 前第二版優先 PC2／PC3 實質分層及 Q1–Q5 重分。核心與畫面由側邊工作交付；此處提供獨立的 Runner 驗收，不重寫核心、Demo builder 或畫面。

## 最新固定候選驗收

核心 PR #22 `1ca3834` 與歷史 PR #20 組合 `46b8904` 已再次通過 **43／43**，包含 ROM、CMake、curl 實際 Runner 與不可變歷史反例。詳見 [最終候選摘要](驗收證據/第二版Runner最終候選摘要.json)。其後合入 `c6bdf9f` 的 UI／導航更新，核心目錄 bytes 不變，整合後另跑完整測試。下方保留較早預覽的固定範圍，不與新結果混述。

## 本次固定範圍

- Runner：本分支合入 main `0e20c6e` 與歷史修正 PR #20 `da0a4c2`，合併 commit `30719a37b8077f4184dd5565653f995b4637460b`。
- PC3 核心：`3ddb6dcfbe1bd877157d5aef10aea2a9c6a3c65d`。執行前從側邊工作建立獨立快照；之後逐檔以 Git blob 比對，核心與六包資料等 27 個檔案都與此固定 commit 相同。不是在測試途中追隨可變檔案。
- 執行範圍：真實 Runner.start_file／analyze_offline／supplement_file／read_engineering、獨立 Python worker、重新建立 Runner 讀取保存紀錄。只用今日 runtime-v2 六包；OFFLINE，不呼叫 API、不執行匯入 binary，不重啟或部署網站。
- 完整程式檔案清單及 hash、archive hash、run／context／profile、各項結果見 [驗收摘要](驗收證據/第二版Runner分層與歷史摘要.json)。原始 archive、解包、工程 blob 留 Fresh 忽略目錄 `var/validation/v2-runner-preview-01/`。

## 實際結果

**43／43 檢查通過，205.187 秒。** 這是三格式加歷史反例的總驗收時間，不是單案使用者等待時間或模型耗時。

| 格式 | 補件前 | 運作材料補件後 | 追加查核數量 | 原成品／PC2 |
|---|---|---|---|---|
| ROM | Needs Investigation；PC3 UNKNOWN | Affected；PC3 SUPPORTED | 1 → 2 | hash、PC2 條件不變 |
| CMake | Needs Investigation；PC3 UNKNOWN | Affected；PC3 SUPPORTED | 1 → 3 | hash、PC2 條件不變 |
| curl | Needs Investigation；PC3 UNKNOWN | Affected；PC3 SUPPORTED | 1 → 3 | hash、PC2 條件不變 |

三條補件逐一檢查實際新增檔案，全部只在 `runtime/`；沒有換 source、library 或 binary。Q1 為 PC1，Q2／Q3／Q4 為 PC2，Q5 為 PC3；既有五個 Query ID 保持相容，profile 明確為 runtime-v2。補件前後第一個 DQ-ID 相同，收到收據才增加其引用材料的查核，完整材料驗證後才標 VERIFIED。

CMake 再測一條反例：先補「另有尚未交付的網路入口」，再交已知入口的運作資料。運作條件可支持，但新工程仍 Needs Investigation；原 M-ID／source context 及未決聲明保留，沒有被最新補件蓋掉。原工程 run／blob 與現象也保留。此項依賴 PR #20。

## 使用方式

在具備第二版核心及 PR #20 的固定候選 checkout，用已安裝專案依賴的 Python 執行：

```bash
python scripts/validate_v2_runner.py   --source-root /absolute/path/to/reviewed-checkout   --output /absolute/path/to/new-ignored-validation-folder   --candidate-label FIXED_COMMIT_SHA
```

程式預設从同一 checkout 讀 `data/catalogs/fresh-pc3-runtime-v2.json`；若核對分開保存的已驗資料，可另給 `--data-root`。output 必須是不存在的新資料夾，保留 progress.json、summary.json 及完整 Runner 保存紀錄。expected outcomes 只在驗收程式，不進產品判定邏輯。

## 發布前仍須完成

1. 整合端合入固定第二版核心／畫面與 PR #20，對最终共同 commit 跑完整 pytest、schema 及必要整合檢查；本次組合驗收不能取代最終 Git commit 的 CI。
2. 網站第二版驗收兩個初始包：完整包直接 Affected；缺件包工程待查→真實 Live 補件指引，到此結束。完整補件能力另於工程驗收保留，不要求上台操作。前輪 `5918858` 的網站 Live 是第一版證據，不能改名當第二版驗收。
3. 新舊 profile 不混述：原包沒有新運作收據時，用新版重新分析可能仍待查；舊保存結果保留原解釋。已驗實作阻斷的 Not Affected 不要求額外運作測試。
4. DQ 的 RULE_GAP 來自規則，模型追加調查另有模型呼叫證據；不能將此 OFFLINE 記錄說成 AI 自主產生問題或客戶實機驗證。

本次未修改 Frankie.md／Integration.md，不調整他人 checkout 或部署。資料皆為今天重新建置的同成品正常觀測，沒有沿用前一天 Demo。對應 D01／D02／D03／D06／D08／D09 與 R01／R06／R07／R11。
