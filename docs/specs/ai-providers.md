# AIP：OpenAI API／Codex CLI 執行來源規格

更新：2026-09-13。狀態：**草案**。入口：[主規格](../../spec.md)。

本文件描述待實作的雙來源功能。既有 OpenAI API 路徑不代表 Codex CLI 已接通；以下新增介面、限制與驗收條件皆不得當成已完成的保證。

## 1. 目標與目前基線

讓使用者在同一個 CVEvidence AI 調查功能中，選擇 `openai_api` 或 `codex_cli`，共用工程證據、受控調查工具、引用驗證與歷史紀錄。Codex CLI 路徑以後端已登入的 ChatGPT 帳號執行，不要求另外提供 OpenAI API Key。

核對基線：Git `8e10efdaee1a814630e3d4c3cb5bdb0dcebf2092`。

| 位置 | 現有行為 | 本功能需處理 |
| --- | --- | --- |
| [核心 AI](../../src/cvevidence_core/ai.py) | 直接使用 Responses API；工具循環依賴 function call 格式 | 抽離供應者格式，保留共用調查與驗證邏輯 |
| [AIService](../../src/cvevidence/ai_service.py)／[worker](../../src/cvevidence/ai_worker.py) | 設定與執行環境要求 OpenAI Key／model | 依來源檢查設定與啟動對應 Adapter |
| [AIStore](../../src/cvevidence/ai_store.py) | AIRequest v1.0；成功紀錄要求 response_id | 新格式版本化，接受可驗證的來源原生收據並保留舊格式 |
| [AI 工作台](../../src/cvevidence/ai_workspace.py) | 固定 OpenAI 文案、外送同意與 180 秒期限 | 來源選擇、狀態與帳號／費用提示 |

現有 `transport` 注入會標示 SIMULATED，不能拿來假裝 Codex LIVE 接線。

## 2. 範圍與角色

第一版採本機單人、Windows 瀏覽器＋WSL Linux 後端。沿用 Runner／Python／Streamlit，不新增 HTTP API 服務；先使用一個調查 agent。

包含雙來源 Adapter、來源選擇、設定檢查、共用調查流程、失敗處理、版本化保存及驗收。兩個來源皆使用雲端模型；CLI 在本機執行不表示模型推論在本機。

後續再評估多人個別登入與隔離、任務佇列、App Server／串流、UI 即時取消及多 Agent 調查；本版必須支援期限到達或 worker 中止時清理子程序。

- **操作者／本機擁有者**：設定可用來源、模型、預設值、API Key 及 WSL Codex 登入。
- **使用者**：選擇已啟用來源、確認資料外送、查看與重開調查。
- 網頁選 Codex 使用的是後端執行帳號，不能宣稱使用瀏覽者自己的 ChatGPT 帳號。第一版不把個人 Codex 帳號開放為公共或不可信的多人服務。

## 3. 需求

| ID | 必須達成的行為 | 驗收 |
| --- | --- | --- |
| AIP-001 | 可選 API 或 Codex CLI；無法使用時顯示原因並禁止啟動 | AC-01、AC-03 |
| AIP-002 | 兩種認證獨立，Codex 的 ChatGPT 登入模式不需要 API Key | AC-02、AC-03 |
| AIP-003 | 提交前顯示來源、設定模型與費用／額度歸屬，確認必要資料外送 | AC-04 |
| AIP-004 | 兩個 Adapter 共用調查動作、範圍與引用驗證，不各寫一套判定引擎 | AC-05、AC-06 |
| AIP-005 | AI 不能直接改原工程判定；追加觀測仍交核心核對 | AC-05、AC-09 |
| AIP-006 | 期限、步數、修正與工具共用預算；程序退出可追溯 | AC-07 |
| AIP-007 | 不自動切換來源或重送；新嘗試與重複提交能區分 | AC-08 |
| AIP-008 | 保存來源原生執行收據及版本；舊紀錄可讀且不改寫 | AC-09、AC-10 |
| AIP-009 | 同案例比較實測品質、耗時與可取得的用量，不保證答案一致 | AC-11 |

## 4. 使用流程與選擇規則

```text
已保存的工程結果
  → 開啟 AI 調查
  → 選擇來源／查看狀態及額度歸屬
  → 輸入問題／確認外送
  → 凍結本次設定並建立 ai_id
  → 執行與驗證
  → 保存結果或失敗
  → 顯示歷史／由使用者另建調查
```

UI 在「AI 調查」區塊顯示來源、可用狀態、設定模型及以下帳務說明：API 使用操作者的 API 計費帳號；Codex 使用後端 ChatGPT 登入帳號的 Codex 額度。無可靠資料時不顯示剩餘額度或自行估算價格。

選單若不能逐項停用，可只列可用來源，旁邊列出不可用來源與原因；全部不可用時停用開始按鈕。後端必須再次驗證，不能只靠 UI 控制。

- 既有部署未設定新預設值時沿用 API；本機新設定可明確指定 Codex。預設來源不可用時顯示原因，由使用者選擇，不默默改用另一個。
- 切換來源、模型、案件或調查輸入後使舊提交識別失效；影響外送範圍／帳號的變更須重新確認同意。
- 執行中凍結來源、模型、scope 與同意；後續 UI 切換不能影響已啟動工作，也不能把遲到結果顯示到另一案件。
- 同 `ai_id` 與相同輸入重送只讀既有結果或回報執行中；不同輸入重用該 ID 必須拒絕。
- 手動重試或換來源建立新 `ai_id`，並保留原失敗。查看歷史或刷新設定不觸發模型調查。

## 5. 設定與認證

| 來源 | 設定與檢查 |
| --- | --- |
| OpenAI API | 沿用 `OPENAI_API_KEY`、`OPENAI_MODEL`、`OPENAI_REASONING_EFFORT` 與既有操作者設定入口 |
| Codex CLI | 由操作者指定可信 CLI 位置、WSL 執行使用者、模型與必要設定；在相同環境檢查 CLI 版本及 `codex login status` |
| 共通 | 保留 `CVEVIDENCE_AI_ENABLED` 總開關；新增允許來源與預設來源的可信設定，實際名稱在介面實作里程碑定案 |

ChatGPT 登入與 API Key 是不同認證／計費來源；本版 Codex Adapter 須確認使用 ChatGPT 模式，不能因機器有 Key 而悄悄改走 API。登入交給官方 CLI 處理，不讀取或複製憑證內容至 prompt、UI、Git 或日誌。[OpenAI Docs：認證](https://learn.chatgpt.com/docs/auth)

Windows Codex 已登入不等於 WSL 後端已登入。可用狀態只證明設定／必要能力已檢查，不保證帳號尚有額度或模型請求一定成功。一般狀態檢查不做模型呼叫，設置短期限與快取；實際連線驗證另由操作者明確啟動。

模型及 CLI 路徑只能來自可信設定，不能由上傳材料、模型輸出或 UI 任意提供。兩個來源的模型各自配置，不假設模型名稱、可用性或輸出相同。

## 6. 架構與內部介面提案

```text
AI 工作台 → Runner → AIService／受限 worker
  → 共用調查控制器
      → OpenAIAdapter：Responses API ↔ 共用 Decision
      → CodexCLIAdapter：codex exec ↔ 共用 Decision
  → Python 驗證 Decision／執行既有來源工具
  → 下一步或結束 → Verifier／Rules → AIStore → 報告
```

| 介面 | 輸入 | 輸出／責任 |
| --- | --- | --- |
| `AIProvider.check_readiness()` | 可信來源設定 | 可用性、原因、認證類型、模型與版本；不包含秘密 |
| `AIProvider.next_step(context, state, budget)` | 當次必要證據、來源私有狀態、剩餘預算 | 一個共用 Decision＋來源原生 Receipt；不直接改資料或執行證據工具 |
| `AIProvider.close()` | 此次執行資源 | 結束並回收該次程序／暫存；清理也必須受期限約束 |

這是內部 Python 介面提案，不是已存在的 HTTP API。型別與模組位置在 M1 固定；state 不得跨案件共用。

Decision 沿用現有 `investigation_step` 的 action、question、reason、term、source_ids、行號、finding、citations、required_files 欄位與驗證規則。允許動作為 LIST、SEARCH、READ、COMPARE、VERIFY、ASK_USER、COMPLETE；VERIFY 仍由 Python 核心執行。不得新增任意 shell、URL 或 verdict 欄位。

API Adapter 封裝原生 function call／tool output 與 response_id；CLI Adapter 將最終結構化輸出轉為 Decision。共用控制器掌握來源工具、引用修正、scope 與預算；不複製兩套調查循環，也不把 Codex 結果偽裝成 Responses API 回應。

Codex 可透過 `codex exec --json` 取得事件，透過 `--output-schema` 要求最終格式；Adapter 分別驗證事件、程序結束及最終 JSON，不能把 exit code 0 或合法 JSON 單獨當成成功。[OpenAI Docs：非互動執行](https://learn.chatgpt.com/docs/non-interactive-mode)

## 7. 資料、工具與預算邊界

- 重用工程結果、PC 證據摘要與必要片段；原包由 Python 管理，不把整個 repo、其他案件、登入資料或開發聊天送入模型。
- 高權限指令由受控模板提供；上傳文字、外部 CVE 資料與工具回應放資料欄位。正確分隔及 schema 仍不能取代權限與引用驗證。
- CLI 啟動使用固定參數陣列、受控工作目錄及最小必要環境；不拼接上傳字串為 shell 命令。API Key 不傳給 Codex 的 ChatGPT 模式。
- Codex 不應取得任意 shell、檔案修改、瀏覽、MCP／插件或委派能力；個人／專案設定不得意外擴大工具。實際限制須依選定 CLI 版本驗證；只有唯讀 sandbox 不足以證明案件隔離。
- M0 必須證明本版工具限制與資料範圍可執行；若不能達成，Codex 保持不可用並記錄缺口，不能僅靠 prompt 宣稱已受限。
- 第一版可每步啟動獨立 CLI，重建有界的必要上下文；不使用不明的最近會話。之後若改為 resume／持續會話，須明確綁定案件與 ai_id 並重新驗收。
- UI 整次期限先維持 180 秒，沿用核心 PC 路徑最多 12 次、145 秒的內層上限；由外層剩餘期限收緊。前處理、程序啟動、模型、工具與修正都扣相同總預算，不重置計時。
- 修正次數沿用最多一次，且計入呼叫上限；保留一次呼叫收尾。資源不足應如實回報，不捏造 COMPLETE。
- 設置並在 M1 固定輸入、事件、最終輸出及暫存上限；串流讀取時即限制大小，超限或逾時終止整個工作程序樹，保留失敗。
- 用 scope＋source hash＋行號去重片段，明示截斷；先量測耗時、呼叫及可取得的用量，不宣稱已節省某比例 token。

## 8. 保存格式與舊資料

現有 AIRequest v1.0 與成功收據約束不能直接加入任意欄位。M1 定義新版 request／payload schema 與讀取分派；舊格式依原驗證器讀取，不改寫原檔或更動原 hash。

新版至少保存：

- 原有 ai_id、parent_run_id、context_hash、CVE、assessment_id、輸入 hash 與同意。
- provider、認證類型、設定模型／推理強度、實際回報模型（允許未知）、CLI／Adapter／prompt／契約版本。
- 開始與結束時間、mode、status、error_code、調查動作、引用核對及可取得的 usage。
- API 的原生 response_id；Codex 的原生 thread／可取得的 turn 識別、完成事件、程序結果與受控事件摘要 hash。供應者未提供的 ID 不得補造。

來源、mode 與 scope 在 request、payload 及收據間必須一致；provider-specific validator 驗證各自完成條件。缺少可核對的必要收據不能標示 LIVE 成功；收據也不等於供應商認證或 AI 結論正確。

保留原工程 bytes 及判定。新原文若經核心重新覆核，保存為獨立追加結果；補件仍建立新工程快照與 parent。舊紀錄缺少來源欄位時，只有已辨識的原 API schema 可顯示為「舊版 OpenAI API」，不得以目前 UI 選項推定歷史來源。

只保存必要、受控的可觀察執行摘要；不保存秘密或模型內部思考。去識別驗收摘要可納 Git，原始材料與敏感模型輸入／輸出留受控 runtime。

## 9. 錯誤與失敗語意

沿用現有 AIStatus；來源差異先以 error_code 和安全文案呈現，避免任意增加成功狀態。以下為新 Adapter 的映射提案，M1 與契約一起固定：

| 情境 | 狀態／處理 |
| --- | --- |
| 未啟用、未安裝、認證失效或不支援的 CLI 能力 | CONFIG_REQUIRED＋具體原因；不自動登入或換來源 |
| 未同意外送 | CONSENT_REQUIRED；模型呼叫為零 |
| 帳號額度／速率受限 | FAILED＋PROVIDER_RATE_OR_QUOTA_LIMIT；原生可區分時保留細分原因 |
| 整次期限耗盡 | TIMED_OUT；終止子程序並保留結果狀態 |
| 呼叫／大小等本機預算耗盡 | BUDGET_EXHAUSTED；不增加上限強行完成 |
| 錯誤 JSON／欄位／動作 | INVALID_MODEL_OUTPUT；僅在共享預算允許時修正 |
| 引用不存在、跨案件或原文不符 | INVALID_CITATION；不納入判定 |
| 原輸入完整性變更 | INPUT_CHANGED_OR_INVALID；保留原紀錄 |
| 斷線、API 錯誤、未知程序錯誤 | 對應 CONNECTION_ERROR／API_ERROR／FAILED，不能推定成功 |
| 程序中斷或沒有結束收據 | 保持未完成／中斷可見；不重送、不偽造完成收據 |

錯誤文字不回顯憑證、原始命令或敏感上傳內容；換來源或重試由使用者另建調查。

## 10. 驗收案例

本表全部為 **NOT_RUN**，描述新功能的驗收目標；既有測試或歷史 Live 不等於本次功能通過。

| ID | 情境與通過條件 |
| --- | --- |
| AC-01 | 兩來源已設定時可選且路由正確；預設不可用不自動改選；執行中切案件不污染結果 |
| AC-02 | 不提供 API Key，在相同 WSL 執行帳號完成真實 Codex 調查；取得有效收據、至少一次來源工具操作及合法結束結果 |
| AC-03 | 缺 Key、缺 CLI、未登入、錯認證類型或不相容 CLI，各自顯示原因且不執行模型；原 API 路徑完成真實回歸 |
| AC-04 | 顯示正確帳號／費用歸屬；未同意時兩來源呼叫皆為零；切換後端來源／帳號或案件須重新同意 |
| AC-05 | 兩來源接共用調查工具；PC1／PC2／PC3 區分已驗、待覆核及未知；通用 CVE 不因 AI 文字升格為已有規則判定 |
| AC-06 | 提示注入、任意 shell／URL、跨 scope、假引用、多餘 verdict 欄位遭拒；測試 CLI 實際工具與設定，不能只測 prompt 字串 |
| AC-07 | 慢模型、慢工具、過量輸出與修正共用期限／上限；結束後無仍在執行的子程序，原工程保留 |
| AC-08 | 額度不足、斷線與未知錯誤不自動換來源；重複提交不重複計費呼叫；新嘗試有新 ai_id，舊失敗保留 |
| AC-09 | 成功／失敗皆不改原工程 bytes；新證據交核心驗證；舊紀錄可讀且 hash 不變；報告來源與選取的紀錄一致 |
| AC-10 | 模擬輸出、偽造／缺少收據、錯來源或錯 model 設定關聯不能通過 LIVE；未回報 usage／實際模型顯示未知 |
| AC-11 | 同份核准案例固定輸入 hash、程式／提示／規則版本，記錄兩來源的成功率、耗時、呼叫、用量、引用核對及人工覆核；不要求文字相同 |
| AC-12 | 完整 `python -m pytest -q` 與契約一致性檢查通過；再核對實際 UI 與保存紀錄，模擬測試和真實 LIVE 分開報告 |

PR 記錄受影響的 [D/R 規則](../ai/developer-guide.md)：設計／交付 D01、D02、D07–D09；資料與執行 D04–D06、D10；runtime R01–R12。重點對照既有 [A01–A12、A16](../ai/acceptance.md) 的注入、引用、失敗、歷史、scope 與調查效益案例；記錄覆蓋與未覆蓋範圍，不將語法／精確引用測試宣稱為全面語意驗證。

每次驗收附程式 commit、資料 hash、來源／模型／版本、測試類型、實際狀態及日誌位置。未有 API Key、Codex 登入或外送授權時，對應 LIVE 標示 NOT_RUN，不能宣稱雙來源完整驗收通過。實作後再更新本檔及主索引狀態。

## 11. 實作里程碑與責任

| 里程碑 | 交付與完成門檻 | 責任邊界 |
| --- | --- | --- |
| M0 可行性 | 固定 WSL CLI 版本；實測登入方式、JSON 輸出、工具限制、程序終止及可取得的收據 | 執行環境／AI 核心共同核對 |
| M1 契約 | 固定 Provider 型別、設定名稱、schema 版本／相容策略、大小預算與錯誤映射；同步測試 | Frankie 整合契約＋Horace AI 語意 |
| M2 API 抽離 | OpenAIAdapter 與共用循環接線；既有成功／失敗／引用流程回歸 | Horace 核心、Frankie worker／保存 |
| M3 CLI 接入 | CodexCLIAdapter、原生收據、scope、預算與清理可驗證 | AI 核心＋執行整合 |
| M4 UI／歷史 | 選擇、可用性、同意、去重與報告相容 | Frankie UI／Runner／保存 |
| M5 聯合驗收 | AC-01–AC-12 的實際證據；缺口如實保留；審閱後更新狀態 | 整合／QA／覆核者 |

這是模組責任分界，不表示已派出或需要同時啟動多個 agent。實作任務只攜帶相關需求 ID、輸入／輸出、受影響檔案、禁止事項及驗收案例；執行進度放 Issue／PR，避免把日誌累積到 spec。

## 12. 尚待實作階段定案

- M0：選定 WSL CLI 版本是否能滿足工具與資料限制；實際事件欄位及模型回報能力。
- M1：新增設定名稱、確切 schema 版本與 Provider 型別、I/O 大小上限、相容讀取測試矩陣。
- M5：API 與 Codex 真實測試所需帳號、核准案例與覆核證據是否齊備。

這些項目不影響先建立規格；各項完成前仍不得標示對應能力已實作或已驗收。
