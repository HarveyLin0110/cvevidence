# 三個 CVE 的規則與適用範圍

此文件說明今日新寫的規則。所有判定都是可覆核的工程初判，限定於提交的成品與已審查路徑；不等於供應商來源認證、實際部署暴露、成功利用或事故根因證明。

共同要求：元件與 source 版本確認、同 build 身分一致、source/header → object → library → 成品對應、交付範圍完整。條件完整且受影響實作與使用路徑成立才 Affected；確認必要條件被阻斷才 Not Affected；缺件、混版或矛盾則 Needs Investigation。未知修改不能藉由「不符合舊指紋」判安全。

## ROM：CVE-2014-0160

OpenSSL 1.0.1f 原始碼包含缺少必要邊界檢查的 heartbeat 處理。官方修正方法包括升級與重新編譯排除 heartbeat。[OpenSSL 官方公告](https://openssl-library.org/news/secadv/20140407.txt)

今日核對 TLS1.2 server method → SSL_read → ssl3_read → ssl3_read_bytes → tls1_process_heartbeat。必須將 method/dispatch 和實際 libssl 連結；不能只找 symbol 或函式文字。

關閉版本須核對 t1_lib.c 與 s3_pkt.c 的實際編譯旗標、同次預處理輸出，並確認 libssl.a 每個 member、shared link、SDK library、產品 DT_NEEDED/linker map 與 ROM 裡的 bytes 對應。只在一個檔案看到 `OPENSSL_NO_HEARTBEATS` 不足以阻斷。

ROM 範圍由解析實際 SquashFS 取得；多出未涵蓋的檔案或 library 會留下缺口。正常 TCP 入口只綁 localhost，展示程式可達路徑；不能稱為已證明對外部署可利用。

## CMake：CVE-2022-37434

規則核對 zlib 1.2.12／1.2.13 的 gzip EXTRA copy 差異。官方修補加入 extra buffer 邊界條件。[上游修補](https://github.com/madler/zlib/commit/eff308af425b67093bab25f80f1ae950166bece1)、[1.2.13 發行](https://github.com/madler/zlib/releases/tag/v1.2.13)

今日產品透過 inflateGetHeader 取得 gzip header，extra buffer 32 bytes、輸入分段 8 bytes，接受使用者提供的檔案。核對這些使用条件與 libz.a → 實際產品連結；只知道 zlib 版本不能判適用。

正常 extra 16 bytes 與截短 gzip 是功能／錯誤處理測試，沒有執行溢位。`gzip stream ended before trailer` 能由一般 EOF 觸發，不能僅憑它將事故歸因 CVE。

## curl：CVE-2023-38545

官方公告涉及 SOCKS5 remote DNS、過長 hostname、非阻塞握手狀態與 buffer 大小；同為 8.3.0 也可有官方 backport 修補。[curl 官方公告](https://curl.se/docs/CVE-2023-38545.html)

今日分別新建未修與已套官方 socks.c 修補的 curl/libcurl。直接核對 shared link 全部 object 的 source/header hash，並核對 CLI 每個 linked object，包含 tool_getparam 與 tool_operate；沒有沿用第一輪遺漏標頭依賴的紀錄。

檢查 launcher 載入交付 libcurl、使用者 URL、SOCKS5 remote-DNS config、limit-rate=16384 對接收 buffer 的影響，以及正常延遲握手觀測與同成品 hash。官方修補對過長 hostname 的處理變化需和實際 linked socks object 對應。未知 config 不會被推定為開啟或安全。

正常觀測使用短 hostname；沒有傳送溢位測試。此 demo curl 刻意不編入 TLS，展示 HTTP/SOCKS5 更新情境；不宣稱測過 HTTPS。

## 來源審查與限制

`src/cvevidence_core/reviewed_sources.json` 保存已審查的關鍵 source hash，與 package 名稱、九格答案或成品 hash 無關。它是窄範圍規則的版本界線，並非一般 C 語言靜態分析器。未審查的 source 改動、其他 CVE／格式或部署設定需要追加 profile 與工程覆核。

交付 build log 與 hash 可以證明內部一致性；無供應商簽章時，仍不能證明紀錄出自可信編譯環境。AI 引用核對會檢查原文及 locator；AI 的自由文字推論仍另列為待覆核，不得直接覆寫工程判定。
