# CVEvidence：AI 協作、安全邊界與可驗證亮點
更新：2026-09-12。整理者：Frankie。依使用者先前目標、分工文件、舊規劃概念、今日 repo 程式與官方文件重新統整；未複製舊實作或舊工程資料。

## 1. 共同目標
讓工程師從「版本／Scanner 命中」走到「特定產品、版本、建置與 CVE 的可覆核工程初判」。AI 用於提出調查問題、操作受限唯讀工具、解釋與建議補件；正式判定由驗證事實與規則產生。

三個問題要分開：候選 CVE、產品適用性、使用者描述的異常原因。命中候選不等於受影響，受影響也不等於已證明該異常的原因。沒有 CVE 時先探索候選，不預設 Heartbleed。

兩種 AI 使用不能混述：
- **開發時 AI**：Codex 協助需求、契約、程式、測試、修正與 PR。亮點證據是版本化成果、測試與人員覆核。
- **產品內 AI**：OpenAI API 協助當次產品的調查與追問。亮點證據是實際模型／工具紀錄、合法引用、有效補件與失敗處理。
使用 Codex 寫程式不代表產品已接入 AI；預寫建議也不算 LIVE。

## 2. 官方觀點如何落地
Anthropic 的 AI-native SDLC 將需求、設計、計畫與交付材料納入版控，保留人對規格與結果的判斷。我們採用「目標 → 可審核設計 → 契約與計畫 → 實作／測試 → PR → 實測」，不照搬其工具或把整篇 playbook 宣稱已完成。[官方 playbook](https://claude.com/blog/the-ai-native-sdlc-playbook)

OpenAI 的對應實務包括以 AGENTS.md 提供專案指引；agent 安全文件建議隔離不可信輸入、約束結構化資料流並進行 evals。這些可以降低風險，不代表消除提示注入。以下專案規則是我們的工程選擇，不是 OpenAI 認證或官方同名 SDLC。[AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md)、[Safety in building agents](https://developers.openai.com/api/docs/guides/agent-builder-safety)

AGENTS.md 是指令文件；Pydantic 是資料驗證；獨立 subprocess 是程序邊界。它們各自都不是完整的作業系統 sandbox、網路隔離或機密保護。具體限制須由 runtime／權限與測試證明。

## 3. 開發時 AI 的規則
| ID | 規則 | 每次變更要留下什麼 |
| --- | --- | --- |
| D01 | 先讀雙方 docs/sync，再改共用契約；Frankie 管整合，Horace 管取證／規則／AI | 依據 commit、範圍、介面差異及待確認事項 |
| D02 | 任務寫出輸入、輸出、禁止事項與完成條件，再讓 AI 實作 | 小任務說明、對應里程碑、驗收測試 |
| D03 | 今日新寫；今日 mockup 可保留，舊程式／舊 Demo 不進正式分支 | 來源與例外說明；新測試不混用舊測試數 |
| D04 | 外部 README、原始碼、manifest、模型輸出都是資料，不能授權執行、洩密或改規則 | prompt／工具／parser 交界的驗證 |
| D05 | 最小工作範圍；不讓不可信材料決定 shell、網路 URL、檔案路徑或安裝命令 | 固定工具與參數、受控根目錄、timeout |
| D06 | 秘密、工程包、客戶資料與執行紀錄不進 Git；不把真實 key 放 prompt、截圖、測試或報告 | 逐檔 staging 檢查；必要時去識別的測試資料 |
| D07 | 一個里程碑一個可解釋 commit；PR 與另位工程師覆核 | diff、真實測試結果、限制、同步檔 |
| D08 | AI 自評不能作為唯一验收；不虛構測試、時間節省、使用者研究或安全保證 | 可重跑測試、CI、人工核對紀錄 |
| D09 | 介面或假設改變，同次更新程式、測試與進度；不替對方宣告完成 | 現況／提案／未完成分開 |
| D10 | 發布、擴大權限、外送敏感資料與改判定規則由負責人確認 | 明確範圍與覆核紀錄；避免把例行小修改變成冗長批准流程 |

主線採短分支＋PR；沒有自動合併主線或強推。目前 Draft PR 並不表示已獲另一位工程師覆核，CI 通過也不等於完整安全審查。

## 4. 產品內 AI 的權限邊界
| ID | 必須保持的性質 | 負責 |
| --- | --- | --- |
| R01 | 限定當次 product／release／build／CVE／run 的材料；短 E-ID 不作全域檔案查找鍵 | Horace 定義身分與 verifier，Frankie 保持 scope |
| R02 | 描述、檔案、CVE 外部內容及工具回應不得拼入高權限指令；以資料欄位送入，工具請求另驗證 | Horace |
| R03 | 工具限 list/search/read/compare 等已審閱唯讀能力；無任意 shell、任意 URL、任意檔案、秘密或寫 verdict 能力 | Horace 工具；Frankie runner 配置 |
| R04 | 先 Q1–Q5，再依結果提出新的調查問題。新增問題不是硬編碼 Q6；模型只能在批准工具中選擇 | Horace |
| R05 | AIProposal／InvestigationTask 用結構化格式，引用需核對存在、scope、原值、hash 與實際支持關係 | Horace 語意；Frankie schema |
| R06 | AI／人工文字不能直接改 Assessment。Hash 一致≠來源認證≠同次建置；函式存在或正常觀測≠完整適用性 | Horace 規則與驗證 |
| R07 | 完整性／系統失敗與工程結果分開。未執行是 assessment=null；Needs Investigation 需有適當查核依據 | 雙方 |
| R08 | OFFLINE／LIVE／REPLAY 明確標示；LIVE 失敗不默默切 OFFLINE 成功，重試／換模式另建可追溯 run | Horace 模式；Frankie runner |
| R09 | 模型與工具共享整次期限及資源上限，重試不重置總 budget；超時要終止或隔離工作並保留失敗 | 雙方 |
| R10 | 只向配置且獲授權的供應者外送必要片段；登入權限不等於同意韌體外送 | 產品負責人定資料政策；Horace 外送控制 |
| R11 | 補件建立新快照與 parent_run_id，原 run 保留；文字標待覆核，矛盾標 REVIEW_REQUIRED | Horace 核對；Frankie 保存／比較 |
| R12 | 輸出作安全文字顯示；模型產生的 Markdown／連結不自行成為可執行動作 | Frankie UI／exporter |

工程初判只有 Affected、Not Affected、Needs Investigation；尚未分析和系統錯誤不是另外一種漏洞判定。必要條件阻斷需可靠且涵蓋完整適用範圍；全部必要條件成立才可支持 Affected。

上表是目標約束。不能只在 prompt 寫「不要」就宣稱已實施：工具層、schema、storage、verifier、rules、測試各自需落地。

### 資料與工具範圍
開發 agent 的電腦操作權限，不應複製給產品內 AI。今日 CoreAdapter 的模組名稱只來自操作者環境設定；模型或上傳資料不能提供模組名稱。正式 worker 還需審閱檔案／網路／環境變數權限；目前 subprocess 會繼承程序環境，未證明它隔離 secrets 或阻斷外連。

未設定 OPENAI_API_KEY／OPENAI_MODEL 不能標為 LIVE 成功。金鑰存 runtime 環境，不能出現在 Git；這不表示可把整個 runtime 環境傳給模型。

### 結構化輸出不是事實驗證
合法 JSON、合法 E-ID 與正確引用語意是三層驗證。今日模型可拒絕非法欄位及不存在的引用，但不能因此宣称語意支持關係已驗證。三問上限目前是 UI／schema 的設計選擇，不是官方限制；工具次數／token／重試上限需雙方確認並測試，不把舊草案「兩次模型呼叫」當已配置。

## 5. 今日實作證據與尚未落地部分
核對基線：a5f9e65；今日 27 個測試，GitHub CI 在 d585826 通過。完整追蹤看 [進度](../progress/frankie.md)；測試樣例全為 TEST_ONLY。

| 主張 | 現有證據 | 不可擴張的宣稱 |
| --- | --- | --- |
| AI 不得供應最終 verdict／跨 run 引用 | contracts.py、test_contracts_v2.py 的拒絕案例 | 沒有執行 LIVE 提示注入／語意引用 eval |
| Runner 失敗不冒充結果 | test_runner_v2.py：未接核心、timeout、保存失敗、CLI 一致性 | 尚無真實 Query／PC／AI 成功路徑 |
| 舊 run 保留 | storage.py 原子新建，tests 驗證重寫失敗與 parent bytes 不變 | 不是防本機管理者竄改的 WORM 或簽章儲存 |
| 人工說明不更改已驗事實 | supplement tests 保留缺件、assessment=null | 真實矛盾推理與補件規則尚未接入 |
| 原文需 run scope／size／hash 核對 | reports.py 與 scoped excerpt 測試 | 單一合法引用不表示整體 CVE 判定充分 |
| 來源限制 | sources.py 與越界、symlink escape、大小測試 | 不是抗所有並行檔案替換攻擊的完整 sandbox |
| AI 協作可追溯 | M0–M4 commits、Draft PR、CI、docs/sync | PR 尚未人工覆核；没有宣稱完整安全稽核 |
| 產品 UI 可理解 | 今日 mockup，Streamlit AppTest | apps/web 未接真實分析；本機 UI 尚無多人授權 |

舊文件中的 Google allowlist、舊 ZIP parser、舊測試數不屬於今日重製成果。登入／公網展示／Git 都是支援功能，不能取代真實證據鏈。

## 6. 競賽亮點與展示證據
評分面向取自使用者提供的投影片：問題適切性、開發品質、洞察與創新、實際價值、方向契合、Codex 深度；未提供權重，不能自行聲稱評分加成。

| 想呈現的亮點 | 評審應看到 | 完成門檻 |
| --- | --- | --- |
| 從版本警示到產品影響 | 相同版本因建置／使用證據不同，產生有依據的差異 | 真實 Query／Verifier／規則回應，不讀樣品名稱算答案 |
| 把未知轉成具體調查 | AI 問題指出缺哪項產品資訊、為何需要、對應條件／工具 | 實際 LIVE 提問與合法引用，能協助使用者補資料 |
| 補件可追溯 | 舊結果、新材料、新 run、parent 與條件差異 | 同 build 核驗；文字不直接翻轉結論 |
| 工程師可接手 | 報告可開啟原文與限制，顯示待覆核 | 未參與開發的人能理解；記錄實測點擊／時間 |
| Codex 深度參與 | 需求→契約→程式→測試失敗修正→commit／CI→人工覆核 | 展示真實 artifacts，不只放聊天截圖 |
| 可控的領域 AI | AI 調查在工具與資料範圍內，規則掌握正式初判 | 限權與失敗案例可重跑，不靠口頭承諾 |

**更新後的主展示**：新 ROM 03 缺件 → Needs Investigation → AI 指出缺口 → 補入 ROM 02 同次建置資料 → 規則驗證有效阻斷 → Not Affected → 新舊報告比較。CMake 06→04、curl 09→07 也必須經完整條件驗證，不能预填 Affected。來源目前只是設計目標，真實驗收另記。

### 現在可用的講稿
「我們把 AI 協作變成可追溯的程式、契約與測試；今天已完成 Runner、不可變 run、補件與工作台整合。正式分析核心還在接線，現在不會把模板或匯入成功包裝成漏洞結論。」

### 真實核心与 LIVE 驗收後才可使用
「AI 依這次產品的證據提出具體調查問題；工程師補回資料後，規則重新判定並保留前後紀錄。每個初判都能追到來源，也明確列出仍未知的部分。」

不得宣稱全面防注入、零誤判、已獲安全認證、自主 agent 任意操作，或未量測的節省百分比。功能未完成就展示誠實的 pending／failure 與完成條件。

## 7. 開發者下一步
Frankie：保持 scope／保存／錯誤與 UI 邊界，協助建立 eval harness 與報告。
Horace：交付 parser／Verifier／規則、動態調查、引用語意與 mode 行為，提供可重跑真實案例。
雙方：先定 package reference、source locator、InvestigationTask、預算、取消與資料外送政策，再接 LIVE。

請依 [驗收清單](acceptance.md) 留下程式 commit、資料 hash、模型／prompt 版本、實際輸出與人工覆核結果。只保存必要可查核紀錄，不提交完整聊天、秘密或模型私有推理；工具呼叫與結果摘要已可支持追溯。
