# PC 命中細節與最小補件指引

依 2026-09-12 使用者最新要求，結果先呈現具體命中點，AI 補件先呈現最小材料與取得方式；詳細格式展開。交件 [PR #26](https://github.com/HarveyLin0110/cvevidence/pull/26)，已在 `4edebaf` 合入 main `063e581`，保留隊友新增的 OpenSSL 情境、動態 Queries 頁與公告說明。原 CMake 兩包仍可獨立驗收；第二版不在現場補件或重判。

## 畫面與報告

- PC1 顯示保存證據中的實際元件名稱／版本，並列版本來源檔；不將版本辨識單獨稱為漏洞成立。
- PC2 顯示受影響實作、實際入口與必要使用條件，列出對應原文路徑與行號。CMake 會出現 zlib 1.2.12、inflate.c、inflateGetHeader、32-byte extra 與 8-byte chunk 的已保存發現。
- PC3 顯示已核對運作紀錄的來源位置與短原文；UNKNOWN 明列具體缺件，受控正常觀測不升格為漏洞重現或客戶部署驗證。
- 只使用該條件引用的唯一 Evidence ID，不重新搜尋檔案或另判 CVE。原文的 context、來源 ID／hash 與正整數行號需對得上才呈現行號；缺失或不一致不補造。文字報告共用同一組整理函式。

## 補件指引

真實 CMake AI 曾漏列運作規則需要的原始 gzip 樣本，且把故障日誌也列為必要。新增核心收件指引供 AI 參照：CMake 收據＋原始正常輸出＋同次 gzip；ROM 收據＋TLS 日誌；curl 收據＋原始交互＋實際配置。

清單以 CORE_PARSER_CONTRACT 明示來源，依本次 context／CVE／assessment 綁定。它是收件說明，沒有成為已驗證據或修改條件；ASK_USER 仍只表示要求已提出。模型仍可提出新的調查問題，原提案與工具紀錄保留。故障日誌另用於症狀調查，不強制當 PC3 正常觀測的最小材料。

畫面先顯示材料、取得方式、檔案位置；詳細收據欄位、成品範圍與驗收用途展開。現有檔案會標「已收件，仍需核對」，未提供不冒稱存在。舊 AI 沒有此欄位時維持原有呈現。格式限制與受控環境依據如實揭露。

## 驗收與交接

新增 12 項測試涵蓋三格式真包的清單／實際補件檔案對照、提前具備運作資料不再索取、不可變結果、來源錯 context／hash／行號／重複 E-ID 拒絕、UI／報告與折疊清單。注入 transport 明示 SIMULATED，不算 Live。

- `84794cc` 的兩包真 Runner／Live：16／16，第一版 Affected、第二版 Needs Investigation。第二版 Sol／medium 真實 2 次呼叫、24.883 秒，先 LIST 既有資料再 ASK_USER，明列收據、日誌、原始 gzip；故障日誌為可選。沒有實際補件或重判，原工程結果及重開讀取均核對。去除機密的紀錄見 [Live 摘要](驗收證據/PC細節與最小補件Live摘要.json)。
- 合入 main 後的 `4edebaf` 與上述 Live 的 19 個核心檔案 SHA256 全部相同；呈現層則另外驗收，沒有把較早 Live 說成新網站上的呼叫。
- 原有六處舊文案斷言已配合具體條件文字更新，UNKNOWN／scope 核對仍保留。一次 AppTest 冷啟動超過既有 3 秒限制；沒有提高該限制，停止重疊測試後，34 項呈現／Queries 測試全部通過（7.69 秒）。
- 16:24 在本機瀏覽器以實際保存結果核對兩版：可見 `inflate.c` 第 758–769 行、入口 `update_reader.c` 第 9–20 行、32-byte／8-byte 使用條件，以及完整包的正常原始日誌；缺件包清單三項可見，格式與原文細節預設折疊。這是本機結果元件驗收，未冒稱公開站已發布或完整導航已驗。
- `4edebaf` 的 [CI 34683108781](https://github.com/HarveyLin0110/cvevidence/actions/runs/34683108781) 已通過：完整 pytest **262 passed＋23 subtests，172.13 秒**，schema 重產一致。本機 schema 與 diff 檢查亦通過。後續文件提交的最新 head／CI 以 PR checks 為準，沒有更動產品程式。

需由整合端審閱本分支對 result_summary／analysis_view／analysis_report 的小幅呈現修改，再發布主站；本分支沒有更動部署、登入、Runner 保存或共用 contracts。對應 D01/D02/D03/D06/D08/D09 與 R01/R04/R05/R06/R08/R11/R12；不宣稱已完成全域語意驗證或通用 parser。
