# 今日 Demo：兩個獨立輸入

依 2026-09-12 最新確認：第一版確認有影響；第二版需要補件，**展示缺什麼、為何需要、如何取得後就結束，不在現場補件或重判**。先完成實作與操作驗收，講稿另後補。

| 版本 | 上傳檔案 | 操作終點 |
|---|---|---|
| 1：資料齊全 | `01_complete/demo_1_complete.tar.gz` | 工程結果 Affected，展開來源證據與 PC1–PC3 |
| 2：資料不足 | `02_requires_evidence/demo_2_requires_evidence.tar.gz` | 工程 Needs Investigation → 真實 AI 調查 → 顯示具體補件指引，結束 |

兩版各自開新案件，指定 `CVE-2022-37434`。第一版直接上傳完整包即可；它已包含正常運作原始材料，不需要現場先做補件。第二版只上傳初始包，不選任何 `supplement_*`。

網頁也可選「產品／版本樣品」：資料版 `fresh-demo-two-flows-v2`；第一版的 package 是 `demo_cmake_complete_v2`，第二版是 `pc3_cmake_static`。請確認服務已更新到包含此資料版與 runtime-v2 核心的版本；舊保存結果不會自動改成新版。

第二版情境欄可輸入：

```text
產品的更新檔匯入偶爾失敗。我們想確認這個成品是否受 CVE-2022-37434 影響；目前先提供拿得到的工程資料。若資訊不足，請具體說明缺什麼、為何需要，以及由誰在哪裡如何取得。這次只展示調查與補件指引，不在現場補件或重現漏洞。
```

AI 的實際問題由當次證據及模型產生。要能看到必要材料、用途、取得方式及同 build 要求；讀取資料的 Query 和等使用者提供資料的 Query 分別呈現。送出詢問後的「完成」只表示問題已提出，不表示補件已收到或驗證通過。

## 來源與檔案

兩包使用今天重新建置的同一個 `product/update-reader`，成品 SHA-256 為 `124cdf81d567f2f7b86f2a0a3839a33acce5bd388f2b075d5f4a252881d22969`；第一版比第二版多出今日收集的 `runtime/observation.json`、正常操作日誌及 gzip 樣本。沒有複製前一天 Demo 程式或結果。正常觀測是受控本機材料，未證明客戶現場暴露或異常原因。

`catalog.json` 與 `SHA256SUMS` 可核對兩個 archive。判定由核心讀取原始證據計算，catalog 不提供預期判定。下方指令只核對檔案：

```bash
cd demo-inputs/two-flows
sha256sum -c SHA256SUMS
```

三格式完整補件流程仍保留在 `demo-inputs/runtime-v2/`，用於工程驗收，不是這次第二版上台的必要步驟。
