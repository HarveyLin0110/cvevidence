# OpenSSL Demo 與 CVE 對應 Queries 預覽

2026-09-12，Frankie 整合。基線 main e96a5db／PR24，Horace PR22 與 PR23 均已合入。

## 現場輸入

情境 A，選 `demo_openssl_complete_v3`，CVE `CVE-2014-0160`：

> 我們的設備管理介面使用 OpenSSL 1.0.1f，想確認這版韌體是否受 Heartbleed（CVE-2014-0160）影響。這次提供同一建置的韌體、編譯連結資料及正常 TLS 連線紀錄，請按 PC1、PC2、PC3 說明判定依據。

情境 B，選 `pc3_cmake_static`，資料版 `fresh-demo-openssl-zlib-v3`，CVE `CVE-2022-37434`：

> 更新工具解壓縮 gzip 檔案時偶爾失敗，想確認是否與 zlib 的 CVE-2022-37434 有關。目前只有成品與編譯資料，還沒有操作紀錄及輸入樣本，請先分析並告訴我還需要補什麼。

兩段是模擬情境，產品結果由同 build 材料實算，不以描述預填判定。B 可停在補件指引；既有補件功能與驗收保留。

## 具體結果呈現

- PC1：只在保存條件與其唯一引用元件證據確認時，寫出本次 OpenSSL 1.0.1f；另外清楚列公告範圍與修補點。
- PC2：只有同次 runtime-v2 的實作、靜態入口與必要條件都獲支持，才綜合敘述 heartbeat／dispatch 編入且未有效排除；保留原始證據說明。
- PC3：只在保存條件及運作證據均支持時，解釋同成品正常 TCP／TLS 1.2 交互；未知不提升為確認。受控本機觀測不等於客戶實機暴露或已重現攻擊。
- 舊 profile 不套用新版說明；兩個已移除摘要區塊不恢復。

版本資訊根據 [OpenSSL 2014-04-07 官方公告](https://openssl-library.org/news/secadv/20140407.txt)：1.0.1 系列至 1.0.1f 與 1.0.2-beta1 受影響，1.0.1g／1.0.2-beta2 修正，亦可經有效重新編譯排除 heartbeat。這是此 CVE 的歷史修補點，非建議現在部署已停止支援的舊版本。

## 執行前 Queries

`query_preparation.py` 為 UI 準備資訊，讀取 Horace `CATALOG`、`FORMAT`、`QUERY_IDS`、`PROFILE_VERSION`；沒有另一套 verdict 或 AI planner。第一頁輸入／切換 CVE 即更新，第三頁「Queries 如何執行：本次查核內容」預設展開每一項的查核內容、所需材料、PC 層級及待執行狀態。

目前核心共用五類起始 Query，CVE 選擇的是實際查核規則與材料。未知 CVE 不套用已知清單；格式不符明示 Q2 可核身分、其餘將記缺口，不假稱可深入分析。這輪不按 CVE 任意增減核心取證工作；真正 RULE_GAP／MODEL 追加問題仍在分析後依證據產生。

預覽不呼叫模型、不建立 run、不宣稱檔案已通過。執行後仍以保存結果清單為準。對新 Query ID 未交付用途／層級時明示，不猜測。

## 驗收與發布

針對 CVE 切換、未知 CVE、格式不符、預覽無執行、未知／舊版條件不升格新增測試。另實走 OpenSSL 完整初始包、zlib 缺件包、補件、報告、兩請求與多 CVE 切換；結果與固定 head 全套測試／CI／公開部署紀錄寫入 PR 留言。

安全 D01／D04／D06／D08／D09，R01／R04／R06／R07／R08／R11／R12：無 AI 權限或預算擴張、材料不當命令、來源與推论區分、scope 和不可變紀錄保留。這輪不更動 Horace 核心判定語意，也不冒稱新增漏洞測試器。
