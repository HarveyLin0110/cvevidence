> 歷史規劃參考：使用者其後確認今日重製，禁止沿用舊 Python／Demo。現行實作與驗收請讀 docs/sync/Frankie.md 及 docs/progress/frankie.md；本文舊程式現況不表示已納入此分支。

# Frankie 開發任務與整合驗收計畫

規劃日期：2026-09-12。依據《CVEvidence 工具架構與雙人分工確認》文字、兩張架構圖、目前前端及 WSL Python 原始碼。分工文件仍稱草案；下列以其邊界規劃，不代表另一位成員已接受新增責任或已交付核心。

## 1. 結論與責任

Frankie 是流程與整合負責人：讓同一份輸入經 Web／CLI 得到一致結果，且資料、錯誤、補件與報告可追溯。另一位成員負責三種格式解析、唯讀 Query、證據驗證、CVE 規則、AI 調查、補件語意及驗收比對器。

Frankie 主維護 contracts，但欄位語意需雙方確認；不得自行改寫 PC 判定、AI 調查策略或 CVE 適用條件。AI 建議不是正式判定。文件未提供另一位成員姓名，本計畫稱「核心負責人」。

## 2. 現況與差距

| 區域 | 已確認狀態 | 本輪待完成 |
| --- | --- | --- |
| 公開網頁 | HTML／JS 模擬，四步導覽、資料路徑、AI 範本、示例結果與補件 | 移植到文件指定的本機 Python／Streamlit 流程，資料取自 Runner |
| Python 核心 | core.py 有嚴格 Pydantic、ZIP 路徑／大小／hash 檢查 | 與新核心接軌；既有 Run 只有 COLLECTED，assessment 永遠 null |
| CLI | cli.py 呼叫 collect_zip，輸出匯入 JSON | 改為呼叫共用 Runner，支援模式、補件、查詢舊 run |
| AI | AIProposal 有解釋、最多三問與引用驗證介面 | 接核心交付的 OFFLINE／LIVE 模式，不把前端範本冒充 AI |
| 保存／比較 | 公開頁面只有記憶體與示例歷程 | 磁碟不可變快照、run、parent、實際差異與報告 |
| 大型 Demo | 參考 ZIP 約 384 MB；既有上傳器限制 20 MiB，最多 101 entries | 優先本機受控樣品選取；不得直接放大限制假裝相容 |
| 自動查找 | 產品＋版本／路徑欄位及固定候選樣例 | SourceResolver 與材料清單介面，目前沒有真實 connector |

本次為讀碼與規劃，未重新執行測試，也未修改正式 Python 核心。既有登入程式可後續重用，但公開靜態預覽不等於已登入的正式分析服務。

## 3. 與使用者預期對應的操作流程

1. **產品與資料來源**：選產品＋版本、配置過的路徑、既有樣品或 ZIP；可補情境、CVE、舊 Claim、Scanner 候選。產品解析出多個 build 時由使用者選擇。
2. **資料確認與缺件**：顯示候選材料、來源與建置核對、已驗證／待核對／缺失／衝突。缺件不一定阻止部分查核，但完整性失敗必須阻止正式判定。
3. **分析進度與結果**：由 Runner 事件顯示真實階段，呈現 Query、PC、原文與 AI 問題。已驗證事實不足時保持 Needs Investigation；未執行不能冒充 Needs Investigation。
4. **報告與後續行動**：報告含工程初判、證據、限制、未知及待覆核。返回補件後建立新 run，可比較前後條件與證據。

AI 建議、證據瀏覽、補件歷程是可重複進入的工具。UI 禁用只改善操作，Runner 仍須驗證階段與資料範圍。不同產品／版本／CVE 切換時，不得殘留其他 run 的結果。

## 4. Frankie 任務清單與完成條件

| ID／順序 | 交付物 | 依賴核心負責人 | 完成條件 |
| --- | --- | --- | --- |
| F01 必做 | contracts.py、JSON 樣例、介面版本 | 六種模型的欄位與語意 | 成功、缺件、完整性錯誤、AI 錯誤樣例皆可驗證；非法引用／多餘判定欄位遭拒 |
| F02 必做 | Runner 與核心 Adapter | 匯入、查詢、規則、AI 的可呼叫入口 | Web／CLI 使用同一入口；沒有 UI 自行算 verdict；OFFLINE 不呼叫模型 |
| F03 必做 | RunStore、材料快照、保存與載入 | 核心提供材料及 build 身分 | 重啟後可載入；旧 run 不覆寫；半寫入資料不顯示成功 |
| F04 必做 | 最小 SourceResolver＋CLI | 真實樣品註冊表與新解析介面 | 本機指定樣品可完成匯入；路徑不存在／越界／版本歧義有可理解錯誤 |
| F05 必做 | Streamlit 四步工作台 | Runner 事件與結果格式 | 來源→資料確認→結果→報告可完整走通；切產品不洩漏舊結果；雙擊不重複啟動 |
| F06 必做 | 證據與 AI 面板 | 原文讀取、Evidence ID、AIProposal | 引用可開啟本 run 的原文；OFFLINE／LIVE 標示正確；文字材料標示待覆核 |
| F07 必做 | 補件表單、parent_run_id、差異 | 補件核對與重新判定入口 | ROM 缺件→補同次建置→新 run→Not Affected，由規則實測產生；舊 run 保留 |
| F08 必做 | 摘要、複製／下載、報告回補件 | 核心判定理由、缺口與來源 | 報告含 product、release、CVE、run、模式、限制與待覆核；與畫面一致 |
| F09 必做 | 超時、錯誤、重試與整合驗收表 | 錯誤類型與驗收比對器 | 系統錯誤不顯示 Not Affected；LIVE 失敗可顯式另建 OFFLINE run |
| F10 次要 | 完整產品＋版本資料目錄查找 | 產品／build 對照資料 | 多版本不混合、零候選不假稱成功、候選尚未驗證不作證據 |
| F11 後續 | 多人登入、正式公開服務、多來源 connector | 部署與資料存取規則 | 確認身份、每個 run 的存取範圍及來源可達性後再上線 |

F04 先涵蓋單機 allowlist 根目錄與 sample_id。F10 才擴充產品索引及多儲存位置。外部共享磁碟／雲端硬碟／Git／NAS 不在本輪一併實作。

## 5. 第一個整合會議要定案的契約

六個文件指定模型：InputPackage、EvidenceRecord、AIProposal、Supplement、Assessment、RunEnvelope。現有 Manifest／Evidence／Run 不應直接改名就當完成，需要明確轉換或版本升級。

| 模型 | 應確認的最小內容 |
| --- | --- |
| InputPackage | schema_version、package/product/release/build 身分、format、材料列表、來源與核驗状态 |
| EvidenceRecord | run 範圍內 ID、來源相對路徑、內容 hash、原文定位、query_id、驗證狀態、限制 |
| AIProposal | 模式、解釋、合法 evidence_ids、問題、建議材料、引用核對狀態；不可寫最終判定 |
| Supplement | parent_run_id、原始材料或文字材料、提交時間、檔案 hash、核對結果；文字不等於驗證事實 |
| Assessment | verdict、逐條 PC／條件狀態、理由、引用、缺口、衝突、待覆核狀態 |
| RunEnvelope | schema_version、run_id、parent_run_id、輸入快照 ID、CVE、模式、執行狀態、結果、錯誤、時間與限制 |

額外由 Frankie 提案、雙方審核：SourceSpec、MaterialCandidate、RunEvent、QueryResult。保持執行狀態與漏洞判定分離，例如 status=FAILED 不對應任何漏洞結論；assessment=null 代表尚無判定。Needs Investigation 是引擎完成適當查核後的結果。REVIEW_REQUIRED 作為覆核旗標，不混成第四種工程初判。

Runner 介面建議：start(request) → run_id；read(run_id) → RunEnvelope；events(run_id) → RunEvent；supplement(parent_run_id, materials) → new_run_id。CLI／Streamlit 共用這些 Python 入口，首版不必增加 HTTP API。

核心入口的具體名稱由雙方確認；可採 import_package、run_queries、assess、investigate、validate_supplement、read_evidence。由 Adapter 隔離對方內部實作，避免 UI 綁定核心目錄結構。

## 6. Runner 與資料保存設計

建議狀態：CREATED → IMPORTING → VALIDATING → QUERYING → ASSESSING → INVESTIGATING → COMPLETED。依核心介面調整階段，失敗可轉 FAILED／TIMED_OUT；不得在超時背景工作仍寫入時宣告終止成功。COMPLETED 表示流程完成，不代表資料齊全或不受影響。

每次 run 固定 package snapshot、product、release、build、CVE、模式。多 CVE 由父請求建立分開的 CVE 子 run，不能共用一個覆寫中的 assessment。

Runner 管理整次 deadline，傳遞剩餘 budget 給支援的核心呼叫；若核心不可取消，需隔離工作程序或明確等待清理，不能僅用 UI 計時器。模型單次請求與查詢數限制由核心負責人控制，Runner 負責整次限制及 UI 回報。

首版採本機檔案儲存即可：blobs/{sha256}、runs/{run_id}/input.json、events.jsonl、result.json、report.md。先寫暫存檔再原子替換；完成結果不覆寫。run_id 不取自未驗證的使用者路徑；避免重複點擊與 Streamlit rerun 造成重複工作。保存錯誤不可偽裝成功。

進行中事件可追加，結束後快照固定；報告只能由已保存結果產生。實際檔案 hash 相同只證明一致性，不能單獨宣称真實來源或同次建置已認證。

補件差異以穩定材料識別、hash、query／條件 ID 比較，不只比較可能重新編號的 E-001。變更 build 的材料另建查核；文字與證據矛盾保留原文並標記 REVIEW_REQUIRED。

## 7. 開發順序與驗收關卡

**G0 介面凍結**：六種模型、一個缺件 ROM 回應、一個有效阻斷回應、一個完整性失敗回應、OFFLINE／LIVE 行為、函式入口。先約定例外如何回傳，再分頭實作。

**G1 CLI 真實閉環**：受控 ROM 樣品 → 匯入／Query／規則 → 保存 JSON → 重啟讀回。對方核心未到位時用標示清楚的 fake adapter 開發整合，不能算真實判定驗收。

**G2 UI 同結果**：Streamlit 接相同 Runner，重現四步、證據跳轉及 AI 建議。不要繼續把正式商業邏輯疊進現有多層 JS render wrapper。

**G3 補件閉環**：ROM 原始缺件 run → 同次建置補件 → 新 run → 引擎確認 Not Affected → 前後比較 → 新報告。這是主展示，先於三種產品全面展開。

**G4 擴充與異常**：CMake、curl 套同一流程，再加 LIVE、逾時、壞包、引用錯誤、保存失敗與產品切換。不要以沒有實测結果的九格表代替驗收。

**G5 展示準備**：執行比對器、記錄版本與實測結果、準備 OFFLINE 路徑。最終驗收跑 repo 要求的 pytest；結果、失敗與未測項保留，不以展示預期填回報告。

不預設每關一天或保證時數；時程取決於核心交付及介面穩定程度。若黑客松時間不足，優先保留 G0–G3，縮減完整索引、多人公開部署、複雜報表與額外 connector。

## 8. 真實驗收矩陣

| 測項 | 必須觀察到 |
| --- | --- |
| ROM 缺件與補件 | 首次 Needs Investigation；補同次建置後由規則驗證 Not Affected；兩份結果均可讀 |
| CMake／curl | 與對方比對器核對九格實測；CMake 修正為升級，curl 為 backport，不能混述 |
| Web／CLI 一致性 | 相同 snapshot／CVE／OFFLINE 模式，忽略 run_id／時間後的結構化結果一致 |
| 完整性錯誤 | hash 不符／混版／竄改停止判定，呈現 integrity error，不顯示安全結論 |
| AI 出錯 | 非法引用／timeout 與正式規則結果分開；若已有有效規則結果，明示 AI 未完成及結果適用限制 |
| 補充文字 | 只存待覆核材料，不自行解除未知或把 Needs Investigation 改為 Not Affected |
| 隔離與保存 | 切產品、切 CVE、重啟、重複點擊均不串資料、不覆寫舊 run |
| 分析不執行輸入 | 匯入資料包不執行 binary／shell／build；建置在分析流程之外 |

## 9. 建議直接交給核心負責人的交接清單

請提供：三種格式的支援版本與最小樣品；解析／查詢／規則／AI／補件／原文讀取入口；六種模型的 JSON 樣例；錯誤類型；OFFLINE／LIVE 模式要求；查詢進度與取消能力；ROM 補件來源與預期比對器。

新增來源查找的責任建議：Frankie 實作選擇、受控位置解析、目錄索引與候選畫面；核心負責人提供材料分類及資料包身分／建置驗證。此項是依新網頁需求補充的提案，原文件未明確分配，需雙方確認後排入正式任務。

開發協作：Frankie 主維護 contracts／runner／storage／ui；核心負責人主維護 parsers／queries／rules／ai。先合約 PR，再一條 ROM 整合 PR，再 UI 與補件 PR；介面變更附新舊 JSON 與相容性說明。AI 生成內容由負責人審閱，不把另一路工作的假設默默寫入正式契約。
