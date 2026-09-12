# F14 分析畫面與接線契約提案

日期：2026-09-12。狀態：待整合端確認的設計，尚未實作完整分析畫面。
依據：F12 39f922f、F13 f4f9f61、Horace 7535246 的核心接線提案。

## 分工及開發順序

Frankie 在 cvevidence-fresh／8506 開發結果呈現、補件互動與報告。整合端在 cvevidence-integration／8505 負責核心 worker、adapter、正式 schema 映射、登入部署及實包驗收。保留 workspace(st, *, store_root=None) 的選用參數，所有資料存取沿用該 RunStore，不新增全域 runtime 或環境變數切換使用者。

1. F14a：雙方核對真實 OFFLINE 輸出及持久化格式，取得固定、去識別的測試輸出；不先自行擴充 RunEnvelope。
2. F14b：Frankie 實作唯讀分析畫面、五項 query、條件與證據查閱，獨立 commit／PR。
3. F14c：接 AI 調查與待補件頁，獨立 AI 狀態及錯誤呈現，獨立 commit／PR。
4. F14d：補件前後比較與報告，整合端完成實包閉環後共同驗收。

目前兩個 session 足夠。只有新增可獨立驗收、無重疊寫入位置的工作（例如測試矩陣或使用者體驗驗收）時，才考慮另開；不得讓第三處同時修改契約／worker。

## 側邊步驟與放行條件

| 步驟 | 畫面／動作 | 放行條件 |
| --- | --- | --- |
| 1 輸入與資料 | 情境、CVE、產品版本、檔案／受控來源 | 永遠可進入；公開部署不允許任意伺服器路徑 |
| 2 收件與範圍 | 候選、來源清單、產品/build/context、缺資料提示 | 請求存在；DRAFT 可閱讀補件問題，不能冒充分析完成 |
| 3 工程分析 | 每個 CVE 的 Q1–Q5、條件、衝突及判定 | 有已保存工程結果；失敗另顯錯誤與重試入口 |
| 4 AI 查核與補件 | AI 問題、工具摘要、引用、需提供資料 | 工程結果已保存；OFFLINE 也可看到工程缺口，但不標 AI 生成 |
| 5 報告與比較 | 下載當次結果、限制、parent 差異、再補件 | 有保存結果即可；不強迫等 AI 成功才可下載 |

未放行步驟反灰並說明原因。AI 頁永遠提供「查看目前報告」及「提供補充資料」的明確出口；缺件不造成死路。重試／補件建立新紀錄，保留原結果。多產品使用独立案件／快照；不以相同 CVE 或檔名混用來源。

## 核心欄位到 UI

| 資料 | 呈現與限制 |
| --- | --- |
| input.sources | 來源清單；S-ID/hash 是資料身分，不標為已證實工程事實 |
| analyses[] | 一個 CVE 一份結果；最多五項，各自狀態；不產生整批安全燈號 |
| queries[] | 固定五項，保留 COMPLETED／COMPLETED_WITH_GAPS／CONFLICT；PC1/PC2/PC3 分組需依正式 profile 映射，不自行猜分組 |
| evidence[] | E-ID、原值、witnesses、X-ID 與理由；原文透過同 run/context 工具查閱 |
| assessment.conditions | 原樣保留 SUPPORTED／BLOCKED／UNKNOWN；不能硬轉舊 TRUE/FALSE 而遺失語意 |
| assessment.verdict | 僅核心回傳的 AFFECTED／NOT_AFFECTED／NEEDS_INVESTIGATION；null 顯示未產生判定 |
| conflicts / statement_reviews | 衝突與 M-ID 人工說明分區；說明不是已驗事實，不能翻轉判定 |
| gaps / next_steps | 缺少什麼、目的、同 build 要求；連到補件入口 |
| ai.tasks / excerpts / calls | 問題、目的、允許的工具摘要、原文引用、模型與狀態；不是模型內部思考，也不宣稱已驗證語意 |
| summary | 組裝摘要；與原始 assessment 不一致時不可用摘要覆蓋工程結果 |

## 持久化與執行建議（待確認）

- 優先沿用 F12 每 CVE 子 run；adapter 對每個子 run 提供對應的單 CVE 結果，避免 UI 再產生第二套 run ID。
- 建議新增有版本的工程分析 payload；由整合端確認放入新版 envelope 或獨立附檔。UI 僅讀正式保存格式，不直接執行分析或反序列化 VerifiedEvidence。
- 工程結果先原子保存。AI 每次執行建獨立識別、parent 工程 run/context、mode/status/時間及錯誤；AI timeout 不改寫工程結果。重新 verify 必須在使用證据的同一程序完成。
- AI OFFLINE、LIVE、REPLAY 與完成／超時／缺件分開顯示；REPLAY 明示舊紀錄，不算本次模型成功。
- ingest worker 保持不接收 AI key；可信任 AI 階段才讀操作者配置。登入不等於授權外送產品資料，外送政策由部署流程明確處理。
- 人工工具收據 F13 與核心階段事件、AI 工具紀錄分別呈現，不將缺少結束紀錄標為成功。

## 驗收與安全規則

對應 D01/D02/D07/D08/D09、R01/R05/R06/R07/R08/R09/R11/R12。

- UI 測試：DRAFT 反灰；工程完成／AI 超時仍有結果；未知 CVE assessment=null；五項 query 缺件／衝突；多 CVE 切換不混 scope；補件和報告出口可達。
- 輸出安全：惡意 HTML、Markdown、URL 以安全文字呈現，不自動執行或載入外部資源。
- 整合測試：9 個初始包與 3 組同 build 補件，保留檔案 hash、核心 commit 與實際結果；UI fixture 通過不算真實 CVE 驗收。
- AI 驗收：真實 LIVE 與 API_ERROR／TIMED_OUT／INVALID_CITATION 狀態獨立核對；未呼叫模型不宣稱 LIVE。
- 每批依 AGENTS 跑完整 pytest、schema 一致性及 CI；PR 明列已完成、測試證據及尚未串接處。

## 接線需回覆的具體資訊

整合端提供：正式 schema／保存欄位、工程執行及 AI 另跑入口、每 CVE scope 的結果範例、Q1–Q5 的 PC 分組來源。確認後 Frankie 直接實作 F14b，不需使用者重複確認。
