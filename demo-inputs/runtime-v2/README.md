# 第二版：PC2 完整，PC3 等待實際運作證據

這六包為 2026-09-12 比賽期間的新產出。沿用的是**今天已重新建置的相同成品**，再於今天收集正常運作紀錄；沒有使用前一天 Demo_3x3 的程式、資料或結果。來源及成品 hash 見本目錄 catalog.json。初始包包含完整 PC2，補件只增加 runtime/ 的材料，未替換 binary、library、原碼或建置證據。

| 展示 | 初始上傳 | 同成品補件 | CVE |
|---|---|---|---|
| curl，網路配置對照 | pc3_curl_static.tar.gz | supplement_pc3_curl_runtime.tar.gz | CVE-2023-38545 |
| CMake，建議主展示、處理較快 | pc3_cmake_static.tar.gz | supplement_pc3_cmake_runtime.tar.gz | CVE-2022-37434 |
| ROM／TLS | pc3_rom_static.tar.gz | supplement_pc3_rom_runtime.tar.gz | CVE-2014-0160 |

## 網頁操作與講法

1. 建立指定 CVE 案件，上傳初始包（或從示範資料選擇同名案例）。curl 現象可填：「更新程式經 SOCKS5 proxy 下載，偶爾握手延遲；請確認此成品是否符合 CVE-2023-38545 的工程條件。」
2. 執行工程查核。看 PC1 元件、PC2 成品實作與靜態路徑，再看 PC3 尚無實際運作證據。五項起始 Query 的 Q5 會提出補件要求，追加問題有獨立 DQ-ID。
3. 可執行獨立 AI 調查。模型依本次資料提出 READ／SEARCH／ASK_USER；畫面分清 MODEL 與 RULE_GAP，詢問送出不等於使用者已補齊。
4. 在**同一工程案件**按補件，選對應 supplement 包，再做工程查核。不要當成新初始包上傳。原案件及 AI 紀錄保留。
5. 查看 PC3 原始輸出、收據中的同成品 hash、配置與來源；查看補件前後工程結果的 followup_query_changes。PC2 證據不變，補件才帶來 PC3 支持。

三組實測皆為 PC2 支持／PC3 未知的 Needs Investigation → 加入充分、同成品的運作資料 → Affected 工程初判。這是測試的觀測結果，程式不從檔名或本文件讀答案。已驗證的修補阻斷仍可在 PC3 未觀測時判 Not Affected，不要求每個案件都執行動態測試。

## 五項起始查核與持續追加

| Query | 檢查內容 | 層次 |
|---|---|---|
| Q1_COMPONENT | 元件與 CVE 候選 | PC1 |
| Q2_BUILD | 建置身分、實際編譯與功能設定 | PC2 |
| Q3_IMPLEMENTATION | 脆弱實作及修補 | PC2 |
| Q4_BINDING | 成品／library 綁定與靜態輸入路徑 | PC2 |
| Q5_PATH | 同成品部署／運作的收據、原始輸出與配置 | PC3 |

若只有 runtime/observation.json，核心會核對成品身分，再新增收據引用的原始 log、trace、配置或樣本問題。檔案缺少／未驗證會保持未知；格式或 hash 不符會要求覆核。追加問題依新快照重新計算、沿用穩定 ID 並在歷史中比較，不是永久固定的 Q6，也不會無限自動執行。

## 真實證據及界限

- curl：同 binary 的正常 SOCKS5 remote-DNS wire bytes、延遲交互、下載配置及命令結果。
- CMake：同 update-reader binary 讀正常 gzip extra/chunk 的原始輸出與樣本。
- ROM：同 binary 的 localhost TCP/TLS 正常往返輸出。
- 三者皆為 CONTROLLED_LOCAL_OBSERVATION；不是客戶實體設備驗證、來源認證、漏洞利用重現或已證明異常原因。收據與 SHA-256 只能支持材料一致性。解析器不執行使用者上傳的任何命令或檔案。
- 今天僅支援這三個已審查格式。通用 PCAP、截圖 OCR、任意 FW 指令自動理解留待後續；未支援材料保持未知並要求原始、可核對輸出。

在此目錄執行 `sha256sum -c SHA256SUMS` 核對六包。產生器為 tools/demo-data/runtime_demo.py，僅供操作人員對今天可信任的 factory build 重收正常紀錄；現有输出不可覆寫。全套 archive 約 32 MB。
