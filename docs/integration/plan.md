# CVEvidence 全部整合任務與 main 發布規則
更新：2026-09-12。維護：整合 session。授權來源：使用者要求「規劃所有整合任務、判斷足夠時主動上 main、週期抓取專案狀態」。
此規則更新先前「不自動 merge main」限制；保留 patch 審閱、測試與 GitHub 保護，不再每次詢問相同合併授權。

## 工作方式與責任
- 整合：cvevidence-integration worktree、codex/integration-*、8505；讀取雙方提交成果，不在另一方 checkout 改檔。
- Frankie：codex/frankie-feature-development、cvevidence-fresh、8506；UI/CLI、請求、多CVE、Runner、保存/追蹤/報告、contracts提案。
- Horace：codex/horace-fresh-core；parser、Query、Verifier、profile/規則/Claim、AI/工具語意與資料製作。
- 只由各作者更新自己的同步檔；整合端維護 docs/sync/Integration.md、本計畫及 docs/releases。
- 功能透過分支/SHA＋介面樣例＋測試結果交件。整合端做相容性修正與跨模組驗收；涉及核心語意變更先回交作者，不自行寫第二套規則。
- 新功能尚未完工不阻礙已有可用里程碑進main；但不得使既有功能回歸，且未實作入口須停用並標明NOT_RUN。

## 任務與依賴
| ID | 整合任務 | 交件依賴 | 驗收完成條件 | 現況 |
|---|---|---|---|---|
| I00 | 分支/目錄/埠隔離、版本清單、主線發布 | 雙方SHA | worktree乾淨，保留兩方歷史，PR與可回復SHA | 已完成；本輪建立main基線 |
| I01 | 正式資料catalog及收件 | Horace demo-inputs/parser | 12包hash、9包收件、產品/build/context一致，不執行binary | 已驗收 |
| I02 | 來源list/search/excerpt/compare | Horace唯讀工具 | scope/原文/hash核對；跨來源、竄改、binary和超限失敗可理解 | 已驗收 |
| I03 | 同build delta/文字補件 | Horace validator＋Frankie保存 | 3組新snapshot/parent、父檔不變、錯build/衝突拒收、文字不改判定 | 收件層已驗收；分析重跑待I07 |
| I04 | 情境無檔案與多CVE請求 | Frankie request功能 | DRAFT不當收件完成；最多5CVE獨立run、共用固定archive、重試去重與並發一致 | Frankie開發中 |
| I05 | 分析階段契約與錯誤映射 | 雙方schemas/樣例 | QueryResult、Condition、InvestigationTask、独立工程/AI狀態相容，未知欄位與非法引用拒絕 | 等交件 |
| I06 | Q1–Q5取證與Verifier | Horace collect/verify | 五項真實回應各自呈現PC1/PC2/PC3，source不冒充fact，缺件/失敗分開 | 等正式核心 |
| I07 | assessment/Claim與補件重判 | Horace assess＋I03/I06 | 真實ROM03補件形成可靠阻斷；CMake/curl必要條件成立才Affected；未知不猜答案 | 等I06 |
| I08 | 動態AI調查與建議UI | Horace investigate＋Frankie面板 | 問題/READ/SEARCH/ASK_USER可追蹤；引用scope/hash/語意核對；不固定Q6、不改規則verdict | Horace本機驗收中 |
| I09 | OFFLINE/LIVE/REPLAY、預算及取消 | Horace模式＋Frankie Runner | deadline共享，timeout終止；LIVE失敗不暗轉成功；離線不呼叫模型；重試另run | 等分析介面 |
| I10 | 請求/工具/AI事件、重啟與歷史 | Frankie保存/追蹤 | 去重、半完成恢復、事件對應run/context；壞歷史不拖垮UI | 基礎容錯已完成，其餘待交件 |
| I11 | 報告/比較/匯出與回補件 | Frankie報告＋I07/I08 | 畫面/JSON/報告同一run，涵蓋條件、缺口、引用、限制、mode與覆核旗標 | 收件報告已驗收 |
| I12 | 九格工程＋三情境LIVE驗收 | Horace比對器＋I04–I11 | 每格記實際輸出/資料hash/程式SHA；工程與AI分開統計，非預填 | 未完成 |
| I13 | 安全與錯誤整合驗收 | 雙方邊界實作 | 提示注入/越界/錯引用/混build/超時/無金鑰/存檔失敗；可重跑證據，不只prompt約束 | 基礎邊界已測，AI安全待交件 |
| I14 | 多人登入與公網服務 | Frankie登入/授權/部署 | 不影響既有OAuth client；allowlist與run權限、secret配置、callback、外送範圍確認後再公開 | 後續階段，未交件 |
| I15 | 可重現展示、文件及結案 | 前述需展示功能 | 新環境依文件啟動；主展示實走；main CI成功，待辦/限制與回復版本明確 | 未完成 |

優先順序：I00–I03基線 → I04/I05 → I06/I07（ROM主線）→ I08–I11 → I12/I13 → I14/I15。
I14不得阻塞本機功能里程碑；未交付登入時維持127.0.0.1，不因進main自動公開服務。
正式完成須逐項驗收；若團隊決定延後I14或REPLAY等項目，須記錄使用者的範圍決定，不自行把待辦改完成。

## 每個PR進main的門檻
1. **範圍可審查**：輸入/輸出/行為/失敗路徑與受影響任務ID明確。整合負責人實際審閱確切patch，記錄發現及處理；不能只看CI綠燈。
2. **來源已知**：固定双方commit與資料hash；沒有用未提交工作、舊Demo或資料名稱當答案。Git只保留已批准的今日demo-inputs；客戶資料、secrets和runtime不進Git。
3. **契約不混用**：新舊保存資料可讀或有明確遷移/隔離策略；source/fact、工程/AI、execution/verdict分開；禁止未驗值升格。
4. **測試足夠**：目標head與main基線的相容測試成功；pytest、schema一致性及與變更相關的實包/負向/UI驗收。純文件變更不用重跑全套昂貴實包。
5. **有真實可用路徑**：基線可匯入/查閱/補件/報告，即可進main；正式分析功能只有實包/規則驗收後才啟用。未完成項目明示NOT_RUN。
6. **GitHub狀態**：PR不是draft，沒有CHANGES_REQUESTED/未處理的實質review或衝突，最新head CI成功；遵守現有required reviews/checks，不使用admin bypass。使用者已授權整合負責人作為此流程審查者；沒有偽稱另一位人類已approve。
7. **合併與競爭檢查**：merge前重新讀head/main，若main有新提交則更新整合分支及必要測試；API用精確head SHA合併，採merge commit保留双方面歷史，禁止force。不要把基於另一功能分支的PR直接當已main合併。
8. **合併後**：核對main包含目標head、CI及服務操作。記錄parent/main SHA與PR。若服務回歸，先恢復之前已驗證服務版本；程式回復走revert PR，不reset/force main、不刪保存資料。

## 每15分鐘的巡檢
排程綁定本整合對話，名稱「CVEvidence 整合巡檢與 main 驗收」，automation ID cvevidence-main。
- 先讀最新使用者範圍與同步；不延續已取消工作。若另一整合操作尚在執行，避免競爭改checkout/合併。
- fetch後記錄main、兩個開發head、整合head、PR/review/CI和8505狀態；本機狀態放var/integration-watch，不提交無變更心跳。
- 有新SHA時閱讀diff和交件文件；尚未交件/測試失敗就回報確切缺口，保持作者開發所有權。
- 達門檻才整合/測試/更新PR/合main；不能只因時間到了就merge。
- 有成果、需要協作的阻礙或main合併時更新GitHub；同一問題更新原留言，不每15分鐘洗版。通知使用者只報實質變化或需決策。
- 本機排程需要電腦開啟、Codex app執行、WSL/專案可達。離線不保證按時；恢復後先重新核對遠端。
- 全部已同意工作完成後寫結案並暫停排程；等待外部交付時繼續巡檢，不冒稱完成。

## 發布紀錄
首個候選基線：整合2efa56c（程式1ac9d4b），56 tests＋12 hashes＋9 intakes＋3 delta＋來源/報告，CI34675527610已通過；加入本計畫後將重新核對PR head/CI再升main。
後續每次發布在docs/releases新增或更新可核對紀錄，至少包含PR/head/main-parent、測試、資料hash、已啟用/未完成能力與回復方法。
