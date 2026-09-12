# OpenSSL 完整工程與運作材料

2026-09-12，依使用者指定 OpenSSL 受影響案例，使用 Horace 今日已交付的 `pc3_rom_static` 與 `supplement_pc3_rom_runtime`，由既有核心 delta validator 組成獨立初始包。未執行上傳 binary，未修改成品、library 或 source，未放入預期判定。

產製腳本：`tools/demo-data/openssl_presentation.py`。輸入與輸出 hash、成品 scope 見 `data/catalogs/fresh-demo-openssl-zlib-v3.json`。輸出僅增加同成品運作收據與正常 TLS 原始紀錄；受控本機觀測不是客戶部署或漏洞重現。

查核 CVE-2014-0160；完整資料是否支持 Affected 必須由 Runner 實算。另一個待補件案例使用既有 two-flows 的 zlib 缺件包，不重複複製材料。
