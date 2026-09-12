# 兩種產品用途：OpenSSL 已確認影響、curl 尚缺運作證據

2026-09-12，Frankie 整合。基線 main 0e819b9 已含 Horace PR26 的具體命中位置與最小補件指引。

使用者要求兩個不同類型、符合實務的案例，且待確認案例不能三個 PC 都未知。因此 A 保留 OpenSSL／TLS 管理介面，B 改為 curl／SOCKS5 設備更新下載，使用已交付的完整靜態工程材料、僅欠運作觀測。情境是模擬使用背景，判定與條件必須由核心實算，沒有用描述或檔名預填。

## A：OpenSSL 管理介面

- CVE：CVE-2014-0160。
- 資料包：`demo_openssl_complete_v3`，`fresh-demo-openssl-curl-v4`。
- 兩句輸入：我們的設備管理介面使用 OpenSSL 1.0.1f，想確認這版韌體是否受 Heartbleed（CVE-2014-0160）影響。這次提供同一建置的韌體、編譯連結資料及正常 TLS 連線紀錄，請按 PC1、PC2、PC3 說明判定依據。
- 完整初始包應由本次核心確認 Affected；PC1、PC2、PC3 均須有支持證據。受控本機正常觀測不等於客戶實機暴露或漏洞重現。

## B：curl 更新下載器

- CVE：CVE-2023-38545。
- 資料包：`pc3_curl_static`，`fresh-demo-openssl-curl-v4`。
- 兩句輸入：設備的更新下載器使用 libcurl 8.3.0，客戶回報透過 SOCKS5 代理下載偶爾中斷，請查核 CVE-2023-38545。目前有完整成品與編譯連結資料，但還沒有當次代理設定與連線紀錄，請確認已知風險條件並列出待補資料。

這對應企業分點設備經代理下載更新的調查流程。下載中斷只是背景，不是此 CVE 的特定徵兆，也不據此歸因。

| 面向 | 此次應取得的工程結果 | 還不能推出什麼 |
| --- | --- | --- |
| PC1 | 已辨識 curl／libcurl 8.3.0，版本與原碼相符 | 版本命中不等於此成品的完整漏洞條件成立 |
| PC2 | 已核對未修補實作、launcher／libcurl 綁定，以及 SOCKS5 hostname／buffer 靜態分支 | 原碼有能力不代表當次配置啟用 |
| PC3 | UNKNOWN：欠同成品收據、代理配置與正常交互原始紀錄 | 尚不能確認 remote DNS、buffer／限速與當次交互條件 |

整體 Needs Investigation；驗收要求四共用前提＋PC1一項＋PC2三項共八項 SUPPORTED，只有 PC3 runtime_observation 為 UNKNOWN。未达到這個實測結果就不發布為指定缺件案例。

必要補件由核心清單提供：`runtime/observation.json`、其引用的 SOCKS5 交互紀錄與實際配置；故障日誌可另供症狀調查，不強制當成正常運作驗證必要材料。現場可停在「已确认的 PC1/PC2＋PC3 缺口＋AI 指引」，不要求現場執行攻擊或真的補件。延伸補件仍建立新 run、保留原紀錄。

版本與條件依 [curl 官方 CVE-2023-38545 公告](https://curl.se/docs/CVE-2023-38545.html)：影響 7.69.0～8.3.0，8.4.0 修正；與 SOCKS5 代理端 hostname 解析及交互／buffer 條件相關，因此實際部署資訊會影響判讀。這是該 CVE 的歷史修補點，非目前選版建議。

## 防止選錯資料

第一頁仍依 CVE 顯示 Queries；第三頁若資料格式與 CVE 已審查 profile 不符，明示原因並停用執行，請使用者換正確資料包或建立正確 CVE 請求。避免把格式不符生成的多個缺口拿來當展示案例。未知 CVE 仍可保存不支援紀錄，不產生另一個 CVE 的工程結果。

本輪只新增 catalog 指向既有批准材料，沒有重製或改寫 binary／原碼／runtime；兩包 hash 已核對。程式修改限 UI 防錯、短情境、目錄預設與驗收。核心規則、API 設定、金鑰與歷史不變。固定 head／測試／PR／公開案例 ID 於發布留言記錄。
