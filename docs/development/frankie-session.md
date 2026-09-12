# Frankie 個人開發 session 與整合端分工

更新：2026-09-12。使用者已要求把個人功能開發與跨成員整合分開。本檔是此 session 的工作範圍；共同接口變更仍需協調。

## 工作位置
| 工作 | Session | WSL checkout | 分支 |
| --- | --- | --- | --- |
| Frankie 功能開發 | CVEvidence (2) | /home/frankie/projects/cvevidence-fresh | codex/frankie-feature-development |
| 跨成員整合 | CVEvidence | /home/frankie/projects/cvevidence-integration | codex/integration-handoff |
| Horace 核心 | Horace 的開發環境 | 由 Horace 維護 | codex/horace-fresh-core |

兩個 checkout 已確認；整合端已回覆同意以下分工。各自不跨目錄修改或停止對方服務。功能分支從 b02fc31 建立，既有 codex/frankie-fresh-milestones 保留作交付基線。

## 此 session 繼續開發
- 情境入口、無檔案的資料需求引導與多 CVE 請求管理。
- UI/CLI 操作流程、重複提交控制、產品／CVE 切換與錯誤恢復。
- 保存、人工操作紀錄、補件歷史、報告呈現與下載。
- 共用契約的提案及驗證測試；語意先與 Horace／整合端確認。

主要檔案：src/cvevidence/workspace.py、cli.py、storage.py、reports.py，及後續新增的 requests/events 模組。
contracts.py、runner.py 屬共用接口：修改前通知整合端，附新舊範例與相容性說明；不自行推定 PC／AI 語意。

## 移交整合端
- Horace 分支合入、archive.repo_path/catalog、正式樣品取得與 hash 核對。
- core_service/core_worker/adapters/worker 等核心呼叫接線，以及真實資料驗收腳本。
- ROM/CMake/curl 與九包／三補件的整合驗收。
- Horace 後續 Q1–Q5／Verifier／assess／investigate 接線與整體版本發布。

整合端已確認以上檔案責任；跨責任修改前交換 commit 與接口。runner.py 由 Frankie 維護，core_service/core_worker 由整合端維護。

## 服務與資料隔離
8505 已由整合端接管；它確認已正常停止舊 fresh 服務，改由 integration checkout 啟動。
Frankie 開發使用8506；此分支 scripts/workspace_service.py 預設8506，提供 --port，PID與日誌按port分開。不得操作整合端8505。
個別 checkout 使用自己的 var/runtime，不共享可寫 run store。既有資料不得刪除、覆寫或自動搬移。

## 交付方式
1. 每個功能里程碑獨立 conventional commit，附實測及未測項。
2. 推送此功能分支，更新自己的規劃／進度。
3. 通知整合 session：commit SHA、變更檔案、接口差異、測試及剩餘依賴。
4. 由整合端在自己的 checkout 合入；雙方不強推，不在對方 checkout 切分支或改檔案。
5. 真實核心未交付的結果保持 NOT_RUN；不以 fixture 或 UI 範本作正式判定。

## 分流時基線
- 44dc613：runtime/history 修正，54項測試通過；已推 GitHub。
- dc95e44：合入 Horace b71926f，包含 demo-inputs 9初始包＋3補件；尚未完成原始包的三格式整合驗收。
- 整合端回報 1ac9d4b 已支援 archive.repo_path、補件hash和正式樣品；12包hash、9/9收件、3/3補件通過。這是整合分支成果，此功能分支不重做相同修改；合入由整合端統一處理。
- Q1–Q5／正式判定／AI 仍未有可整合交付；Horace 的 Live 試跑是他同步的進度，不是本工作台的驗收。
