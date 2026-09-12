# AIP：OpenAI API／Codex CLI 執行來源規格

更新：2026-09-13。狀態：**開發中**。入口：[主規格](../../spec.md)。

共用 Provider、OpenAIAdapter、v2 保存／worker 與來源選擇 UI 已實作；Codex 執行環境／Adapter、完整版本追溯與 M5 聯合驗收仍須完成整合。以下明確區分現有介面與交付要求；程式、模擬測試或既有 API 歷史紀錄不等於本次 Codex／API LIVE 驗收通過。

## 1. 目標與目前基線

讓使用者在同一個 CVEvidence AI 調查功能中，選擇 `openai_api` 或 `codex_cli`，共用工程證據、受控調查工具、引用驗證與歷史紀錄。Codex CLI 路徑以後端已登入的 ChatGPT 帳號執行，不要求另外提供 OpenAI API Key。

原始需求基線：Git `8e10efdaee1a814630e3d4c3cb5bdb0dcebf2092`。本次介面核對至整合 `f61c051`，驗收 harness 為 `2be563e`；後續實測版本與完整測試結果集中於 [驗收與發布紀錄](../releases/)。

| 位置 | 已實作介面 | 仍須驗收／補齊 |
| --- | --- | --- |
| [核心 AI](../../src/cvevidence_core/ai.py)／[providers](../../src/cvevidence_core/providers.py) | `ProviderStep`、`ProviderError`、OpenAIAdapter；兩來源接同一工具／引用循環 | Codex Adapter 整合、兩來源真實調查 |
| [AIService](../../src/cvevidence/ai_service.py)／[worker](../../src/cvevidence/ai_worker.py) | 來源與 `config_id` 路由、白名單設定、v2 串流上限與期限 | 真實 CLI 子程序與環境限制 |
| [AIStore](../../src/cvevidence/ai_store.py) | AIRequest v1.0／v2.0 分派、來源原生收據驗證、原子新建紀錄 | 每筆程式／prompt 版本關聯與聯合相容驗收 |
| [AI 工作台](../../src/cvevidence/ai_workspace.py) | 來源選擇、readiness、同意失效、歷史／報告來源呈現 | 整合版本的實際 UI 與保存紀錄核對 |

未傳 `provider` 的原入口維持 v1；既有 `transport` 或 OpenAIAdapter 的測試 transport 一律標示 SIMULATED，不能拿來假裝 LIVE 接線。

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

目前選單列出兩來源及可用／無法使用狀態；選到不可用來源時停用開始按鈕並列出原因。後端再次核對來源與 `config_id`，不能只靠 UI 控制。

- 既有部署未設定新預設值時沿用 API；本機新設定可明確指定 Codex。預設來源不可用時顯示原因，由使用者選擇，不默默改用另一個。
- 切換來源、模型、案件或調查輸入後使舊提交識別失效；影響外送範圍／帳號的變更須重新確認同意。
- 執行中凍結來源、模型、scope 與同意；後續 UI 切換不能影響已啟動工作，也不能把遲到結果顯示到另一案件。
- 同 `ai_id` 與相同輸入重送只讀既有結果或回報執行中；不同輸入重用該 ID 必須拒絕。
- 手動重試或換來源建立新 `ai_id`，並保留原失敗。查看歷史或刷新設定不觸發模型調查。

## 5. 設定與認證

目前設定由 [ai_config.py](../../src/cvevidence/ai_config.py) 的 `operator_settings()` 讀取；指定環境變數優先於 `CVEVIDENCE_AI_ENV_FILE`。未指定檔案時不自動搜尋 `.env`。

| 設定 | 用途／預設 |
| --- | --- |
| `CVEVIDENCE_AI_ENABLED` | 必須為 `1` 才可啟動產品內 AI |
| `CVEVIDENCE_AI_PROVIDERS` | 逗號分隔允許來源，預設 `openai_api`；有效項目只有 `openai_api` 與 `codex_cli` |
| `CVEVIDENCE_AI_DEFAULT_PROVIDER` | UI 預設來源，預設 `openai_api`；無效或不可用不自動換來源 |
| `CVEVIDENCE_AI_AUTH_REVISION` | 操作者認證設定修訂，預設 `1`；納入設定識別 |
| `OPENAI_API_KEY`／`OPENAI_MODEL`／`OPENAI_REASONING_EFFORT` | API 認證與模型；推理強度預設 `medium` |
| `CVEVIDENCE_CODEX_BIN` | 可信 CLI 位置，預設 `codex`；相同 WSL 後端使用者執行 |
| `CVEVIDENCE_CODEX_HOME` | 操作者指定 Codex 設定／認證目錄；不得由上傳資料提供 |
| `CVEVIDENCE_CODEX_MODEL`／`CVEVIDENCE_CODEX_REASONING_EFFORT` | Codex 專用模型與推理強度；推理強度預設 `medium` |
| `CVEVIDENCE_AI_ENV_FILE` | 由啟動環境指定的可信設定檔路徑；不傳給模型或暴露成 UI 路徑參數 |

WSL 執行使用者由服務啟動環境決定，不是網頁可切換的帳號參數。`provider_configuration(provider)` 回傳 `(private, public)`；只有 public 可交 UI，內容含 `configured`、`reason_code`、`model`、`reasoning_effort`、`auth_type`、`billing_label`、`version`、`mode` 與 `config_id`。`config_id` 為設定摘要識別，不是帳號憑證；後端在開始時重新比較，變更則回報 `CONSENT_REQUIRED / PROVIDER_CONFIGURATION_CHANGED`。

ChatGPT 登入與 API Key 是不同認證／計費來源；本版 Codex Adapter 須確認使用 ChatGPT 模式，不能因機器有 Key 而悄悄改走 API。登入交給官方 CLI 處理，不讀取或複製憑證內容至 prompt、UI、Git 或日誌。[OpenAI Docs：認證](https://learn.chatgpt.com/docs/auth)

Windows Codex 已登入不等於 WSL 後端已登入。可用狀態只證明設定／必要能力已檢查，不保證帳號尚有額度或模型請求一定成功。一般狀態檢查不做模型呼叫；CLI 的短期限、快取及認證身分辨識由其 Adapter 交件確認，不能只靠手動修訂值宣稱能偵測所有帳號切換。實際連線驗證另由操作者明確啟動。

模型及 CLI 路徑只能來自可信設定，不能由上傳材料、模型輸出或 UI 任意提供。兩個來源的模型各自配置，不假設模型名稱、可用性或輸出相同。

## 6. 已實作架構與內部介面

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
| `Runner.ai_configuration()` | 無 UI 認證／路徑參數 | `default_provider`、`providers` 對映；保留舊 API public 欄位供既有呼叫者使用 |
| `Runner.investigate_ai(parent_run_id, *, provider, config_id, user_context, consent, ai_id, timeout)` | 父工程 ID、來源、已確認設定 ID 及當次輸入 | 由 AIService 建立 v2 request，重核設定／同意並保存結果；不接受 UI 任意模型／CLI 命令 |
| `provider.step(*, instructions, packet, history, budget, timeout)` | 受控指令、當案有界 packet、結構化 history、剩餘預算 | `ProviderStep(decision: dict, receipt: dict)`；不直接執行證據工具或寫判定 |
| `provider.close()` | 此次執行資源 | finally 回收；須可重複呼叫；清理失敗不得保持成功狀態 |

這些是內部 Python 介面，不另建 HTTP API。共用型別在 `cvevidence_core/providers.py`：`ProviderStep` 為 dataclass，`ProviderError(status: str, code: str)` 僅傳有限失敗狀態與安全代碼。Adapter 必須提供 `provider_id`、`model`、`reasoning_effort`、`auth_type`、`mode`、`version` 屬性。

`history` 格式為 `[{step_number, decision, result}]`；Adapter 只收到資料副本，不收到 `InputPackage`、來源根目錄或工具 callable。`OpenAIAdapter(config, *, transport=None)` 保存當次 Responses items／call_id 私有狀態，再把 Python 工具結果轉回原生 function call output。這些原生暫存不跨案件共享，close 後清除。

核心入口為 `investigate(..., provider=None)`，延後調查入口為 `investigate_after_engineering(..., provider=None, timeout_seconds=None)`。明確 Provider 路徑輸出 v2；未指定來源維持既有 v1 行為。明確 Provider 一次只綁定一筆工程 assessment，避免已關閉或跨案狀態被重用。

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
- 引用／CLI 選項來源校核的修正最多一次，計入呼叫上限；工具參數錯誤的後續步驟也扣相同預算。保留一次呼叫收尾，資源不足如實回報，不捏造 COMPLETE。
- 已實作上限見下表；CLI 原生事件、輸出與暫存的額外限制由其 Adapter 交件補齊，不假設與 API 回應相同。
- 用 scope＋source hash＋行號去重片段，明示截斷；先量測耗時、呼叫及可取得的用量，不宣稱已節省某比例 token。

| 邊界 | 已實作上限／行為 |
| --- | --- |
| UI／service 調查文字 | 4,000 字元 |
| v2 service → worker JSON | 32,000 bytes；worker 另拒絕超過 32,000 字元的 stdin |
| v2 worker stdout | 16 MiB；串流讀取時檢查，超限終止 POSIX 程序群組 |
| 共用 Provider packet＋history | JSON 編碼合計 1 MiB；超限 `BUDGET_EXHAUSTED / PROVIDER_INPUT_LIMIT` |
| API Adapter 原生 items | JSON 編碼另限 1 MiB，包含其私有 Responses 歷史 |
| 單筆 Provider receipt | JSON 編碼 64 KiB；超限 `BUDGET_EXHAUSTED / PROVIDER_RECEIPT_LIMIT` |
| API HTTP response | 2,000,000 bytes；不把任意長度回應全部讀入 |
| 模型輸出 token 上限 | API PC 模式 9,000、focused 模式 3,000；不推定 Codex 使用相同控制 |

`ai_process.run_worker()` 的 `finally` 清理所在 POSIX 程序群組；它不自動證明能清理跨 Windows interop 或自行脫離群組的程序，CLI 的實際終止測試仍為必要條件。`calls` 是調查呼叫嘗試紀錄，可能包含傳送前耗盡本機預算的項目，不能把筆數當成已送達或已計費次數。

## 8. 保存格式與舊資料

`AIRequest` v1.0 與 `AIRequestV2` v2.0 已分開，`parse_ai_request()` 依 schema version 分派；契約分別匯出為 [ai-request.json](../../contracts/schemas/ai-request.json) 與 [ai-request-v2.json](../../contracts/schemas/ai-request-v2.json)。AIOutcome 維持原格式與狀態集合。舊格式依原驗證器讀取，不改寫原檔或更動原 hash。

目前已保存：

- request 保留 ai_id、parent_run_id、context_hash、CVE、assessment_id、工程／文字輸入 hash、同意、設定模型／推理強度與期限；v2 新增 `provider`、`auth_type`、`config_id`。
- v2 wrapper 與 inner AI 均有 `schema_version="2.0"`；inner 保存來源、認證類型、設定模型及 `adapter_version`。實際回報模型與 usage 留在各筆 calls，允許未知。
- 開始與結束時間、mode、status、安全錯誤碼、調查動作、引用核對與 record hash。
- 成功 calls 必須有一致 provider、連續的 `call_number=1..N`、`status="completed"`。API 必須有非空 `response_id`。
- Codex 成功收據的保存契約要求非空 `thread_id`、`exit_code=0`、`terminal_event="turn.completed"`、64 位小寫 hex `events_sha256`，並拒絕代造的 API response_id。這是儲存驗證要求，CLI 原生事件實测仍須另交證據；未提供的 turn ID 不補造。

**版本追溯仍須補齊後才算交付完成**：每笔 AIRequestV2 必須關聯 code content SHA、prompt SHA 與契約版本；worker 必須比對此次執行版本，不能在程式改變後沿用舊同意。驗收 harness 已記錄程式清單／內容 hash、Git commit、prompt hash 與問題 hash；這不能取代一般產品 AI 紀錄的版本關聯。Adapter／CLI 版本由其實際回傳記錄，缺值保持未知。

來源、mode 與 scope 在 request、payload 及收據間必須一致；provider-specific validator 驗證各自完成條件。缺少必要收據不能標示 LIVE 成功。原生 ID／本地 hash 僅支持格式、完整性與關聯檢查，無法單憑這些欄位辨識所有偽造資料；真實呼叫須有獨立 LIVE 執行證據，收據不能升格成供應商認證或 AI 結論正確。

保留原工程 bytes 及判定。新原文若經核心重新覆核，保存為獨立追加結果；補件仍建立新工程快照與 parent。舊紀錄缺少來源欄位時，只有已辨識的原 API schema 可顯示為「舊版 OpenAI API」，不得以目前 UI 選項推定歷史來源。

只保存必要、受控的可觀察執行摘要；不保存秘密或模型內部思考。去識別驗收摘要可納 Git，原始材料與敏感模型輸入／輸出留受控 runtime。

## 9. 錯誤與失敗語意

沿用現有 AIStatus；來源差異以 error_code 和安全文案呈現。以下為共用核心、OpenAIAdapter 與 v2 service 的已實作映射；CLI 特有原生錯誤碼仍須核對其交件：

| 情境 | 狀態／處理 |
| --- | --- |
| 未啟用、未安裝、認證失效或不支援的 CLI 能力 | CONFIG_REQUIRED＋具體原因；不自動登入或換來源 |
| 未同意外送或已確認設定變更 | CONSENT_REQUIRED；設定變更使用 PROVIDER_CONFIGURATION_CHANGED；不呼叫模型 |
| 帳號額度／速率受限 | FAILED＋PROVIDER_RATE_OR_QUOTA_LIMIT；原生可區分時保留細分原因 |
| 整次期限耗盡 | TIMED_OUT；終止子程序並保留結果狀態 |
| 呼叫／大小等本機預算耗盡 | BUDGET_EXHAUSTED；不增加上限強行完成 |
| 錯誤 JSON／欄位／動作 | INVALID_MODEL_OUTPUT；不把合法 JSON 等同合法 Decision |
| 引用不存在、跨案件或原文不符 | INVALID_CITATION；不納入判定 |
| 原輸入完整性變更 | INPUT_CHANGED_OR_INVALID；保留原紀錄 |
| 斷線、API 錯誤、未知程序錯誤 | 對應 CONNECTION_ERROR／API_ERROR／FAILED，不能推定成功 |
| 程序中斷或沒有結束收據 | 保持未完成／中斷可見；不重送、不偽造完成收據 |

API 401／403 對應 `CONFIG_REQUIRED / PROVIDER_AUTHENTICATION_FAILED`，429 對應 `FAILED / PROVIDER_RATE_OR_QUOTA_LIMIT`；未知 Provider 例外以安全代碼記錄。讀取只有 start、沒有 end 的 attempt 時回傳 `NO_TERMINAL_RECEIPT`，這是讀取狀態，不是新增的成功或工程判定。

錯誤文字不回顯憑證、原始命令或敏感上傳內容；換來源或重試由使用者另建調查。

## 10. 驗收案例

本表是完整驗收門檻，**尚未整體通過 M5**。Provider 核心、service／保存與 UI 已有自動測試，harness 已跑未同意分支；真實 API／Codex、整合版本完整回歸與人工覆核仍須各自留下證據。單元測試通過不直接把包含 LIVE 或人工條件的整列 AC 標為 PASS。

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
| AC-10 | 明確 SIMULATED／缺少收據、錯來源或錯 model 設定關聯不能通過 LIVE；未知 usage／實際模型不猜；原生 ID／hash 不視為防偽認證，真實呼叫另以 LIVE 證據核對 |
| AC-11 | 同份核准案例固定輸入 hash、程式／提示／規則版本，記錄兩來源的成功率、耗時、呼叫、用量、引用核對及人工覆核；不要求文字相同 |
| AC-12 | 完整 `python -m pytest -q` 與契約一致性檢查通過；再核對實際 UI 與保存紀錄，模擬測試和真實 LIVE 分開報告 |

PR 記錄受影響的 [D/R 規則](../ai/developer-guide.md)：設計／交付 D01、D02、D07–D09；資料與執行 D04–D06、D10；runtime R01–R12。重點對照既有 [A01–A12、A16](../ai/acceptance.md) 的注入、引用、失敗、歷史、scope 與調查效益案例；記錄覆蓋與未覆蓋範圍，不將語法／精確引用測試宣稱為全面語意驗證。

每次驗收附程式 commit、資料 hash、來源／模型／版本、測試類型、實際狀態及日誌位置。未有 API Key、Codex 登入或外送授權時，對應 LIVE 標示 NOT_RUN，不能宣稱雙來源完整驗收通過。

可重跑入口為 [validate_ai_providers.py](../../scripts/validate_ai_providers.py)：

```bash
# 僅工程流程＋readiness；沒有 --consent 時模型呼叫為零。
python scripts/validate_ai_providers.py --provider all --output-dir var/validation/aip-check-001

# 操作者明確同意後，才加入 --consent 執行所選已配置來源。
python scripts/validate_ai_providers.py --provider codex_cli --output-dir var/validation/aip-live-001 --consent
```

`--provider` 接受 `openai_api`、`codex_cli` 或 `all`；每次使用新目錄，repo 內輸出須位於忽略的 `var/`。腳本使用已核准的 two-flows 初始包、每案獨立 runtime，核對工程 bytes、scope、來源原生收據、重開結果與引用狀態；Codex 至少須有一個完成的 LIST／SEARCH／READ／COMPARE。結果分別記 PASS／FAIL／NOT_RUN，人工覆核獨立保持 NOT_RUN。exit code 為 0＝自動 PASS、1＝FAIL、2＝NOT_RUN；以保存的 `summary.json` 核對各項原因。缺失的 usage 保持 null，calls 筆數不等於已計費次數；不計算未量測的 speedup。

## 11. 實作里程碑與責任

| 里程碑 | 交付與完成門檻 | 責任邊界 |
| --- | --- | --- |
| M0 可行性 | 固定 WSL CLI 版本；實測登入方式、JSON 輸出、工具限制、程序終止及可取得的收據 | 執行環境／AI 核心共同核對 |
| M1 契約 | 固定 Provider 型別、設定名稱、schema 版本／相容策略、大小預算與錯誤映射；同步測試 | Frankie 整合契約＋Horace AI 語意 |
| M2 API 抽離 | OpenAIAdapter 與共用循環接線；既有成功／失敗／引用流程回歸 | Horace 核心、Frankie worker／保存 |
| M3 CLI 接入 | CodexCLIAdapter、原生收據、scope、預算與清理可驗證 | AI 核心＋執行整合 |
| M4 UI／歷史 | 選擇、可用性、同意、去重與報告相容 | Frankie UI／Runner／保存 |
| M5 聯合驗收 | AC-01–AC-12 的實際證據；缺口如實保留；審閱後更新狀態 | 整合／QA／覆核者 |

這是模組責任分界。實作任務只攜帶相關需求 ID、輸入／輸出、受影響檔案、禁止事項及驗收案例；同一核心檔案保持單一 owner，執行進度放 Issue／PR，避免把日誌累積到 spec。

## 12. 尚待完成的交付

- M0／M3：固定 CLI 版本的工具、資料、認證身分與程序終止實測；核對原生事件及 CLI 專用大小上限，不從 read-only 或功能旗標推定隔離成立。
- M1：每筆 AIRequestV2 的 code／prompt／contract 版本關聯與 worker 比對；一般 AI 紀錄不能只依賴獨立驗收摘要追版本。
- M5：兩來源真實調查、同版本完整 pytest／schema 檢查、UI／重開紀錄核對及人工語意覆核；帳號、模型或外送前提缺失時明記 NOT_RUN。

本功能維持開發中；以上條件完成前，不把相鄰模組的測試、既有 API 歷史 Live 或 TEST_ONLY 收據宣稱為本次完整驗收。
