# Demo 輸入檔：今天重建、可直接交給前端

**第二版主展示請使用 [runtime-v2 操作說明](runtime-v2/README.md)。** 新增六包，把 PC2 完整工程證據與 PC3 實際運作補件分開；預設 catalog 已改選新版。以下十二包及其驗收為今天較早版本的材料與歷史說明。以新 runtime-v2 規則重新分析舊的靜態完整包，可能因缺少 PC3 仍待查；不要套用早期 Affected 結果。舊 run 保留原判定及 profile，查看歷史不會自動重判。

此資料夾就是隊友與展示時選檔的共同位置，隨 Git 一起取得。12 個壓縮包全部來自 2026-09-12 新製作的 builder 與官方重新下載的 OSS；未沿用舊 Demo 的程式、成品或驗收結果。

共約 95 MB，最大單包約 17 MB，直接納入 Git，不需要額外下載 Release 或 Git LFS。請保留 `.tar.gz` 原檔與檔名，避免重新壓縮造成 catalog hash 不同。每包 root 都有 `manifest.json`，副檔名為 gzip tar；核心已支援此格式。前端選檔器也須允許 `.tar.gz`，不能只接受 `.zip`。

## 展示時選哪個檔案

| 情境 | 初次上傳 | 同一成品的後續補件 | 指定 CVE |
|---|---|---|---|
| ROM 主展示：證據不完整，再補齊 | `rom/03_rom.tar.gz` | `rom/supplement_03_rom.tar.gz` | CVE-2014-0160 |
| CMake：使用者先描述更新匯入失敗 | `cmake/06_cmake.tar.gz` | `cmake/supplement_06_cmake.tar.gz` | 現象入口先留空；由元件資料找候選 |
| curl：檢查 SOCKS5 更新下載工具 | `curl/09_curl.tar.gz` | `curl/supplement_09_curl.tar.gz` | CVE-2023-38545 |

操作：先上傳初始包 → 看 Q1–Q5／缺口 → 看 AI 自行提出新問題 → 點「補件」上傳右欄檔案 → 產生新的 snapshot/run → 比較補前、補後證據及工程判定。補件不要當成完整初始包上傳。

初始資料與補件是同一次真實 build；補件只補工程材料，不換 binary。03 的材料來自 ROM 02；06 來自 CMake 04；09 來自 curl 07。不同 build 的包不能拿來補原案件。

## 九個初始包

| 目錄 | 完整工程資料 A | 完整工程資料 B | 缺少部分材料的初始交付 |
|---|---|---|---|
| `rom/` | `01_rom.tar.gz` | `02_rom.tar.gz` | `03_rom.tar.gz` |
| `cmake/` | `04_cmake.tar.gz` | `05_cmake.tar.gz` | `06_cmake.tar.gz` |
| `curl/` | `07_curl.tar.gz` | `08_curl.tar.gz` | `09_curl.tar.gz` |

正式結果由當次程式取證與規則計算；檔名、選項及此表不能當判定依據。此資料夾不存預期答案，也不存 API key 或本機 TLS 測試私鑰。套件內有第三方 OSS 的授權文件。

## 可直接貼入網頁的現象

- ROM：`掃描報告說產品包含 OpenSSL 1.0.1f。我想確認 CVE-2014-0160 是否適用這個韌體，目前只有 ROM 和部分 SDK。`
- CMake：`客戶匯入更新檔失敗，log 顯示 gzip stream ended before trailer。請先查可能原因，再確認相關 CVE 是否適用這個產品。`
- curl：`更新下載會經過 SOCKS5 proxy。我想確認 CVE-2023-38545 是否適用，現場偶爾會有握手延遲。`

正常截短 gzip 的錯誤是檔案不完整的線索，不能說已重現 CVE；curl 正常下載也未執行溢位。畫面需分開顯示「漏洞工程適用性」與「異常原因尚未確定」。

## 取得與核對

輸入包已隨 [PR #2](https://github.com/HarveyLin0110/cvevidence/pull/2) 合入 `main`。隊友更新自己的整合分支後，即可從 repo 的 `demo-inputs/` 選檔。完整工程分析與 AI 核心另由 [PR #9](https://github.com/HarveyLin0110/cvevidence/pull/9) 交件；輸入包已取得不代表網頁分析階段已接妥。

在 repo 根目錄執行：

```bash
cd demo-inputs
sha256sum -c SHA256SUMS
```

`catalog.json` 列出 12 包的 Git 相對路徑、大小、SHA-256、manifest hash、build/release 與補件對應。`data/catalogs/` 中保留各版不可變成品身分；新增 `archive.repo_path` 指向這裡。工程與 AI 驗收進度另見 `docs/releases/`，不要將資料交付完成解讀為所有分析已驗收。
