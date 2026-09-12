# Frankie 個人開發 session 與整合端分工

更新：2026-09-12。使用者已要求把個人功能開發與跨成員整合分開。本檔是此 session 的工作範圍；共同接口變更仍需協調。

## 工作位置
| 工作 | Session | WSL checkout | 分支 |
| --- | --- | --- | --- |
| Frankie 功能開發 | CVEvidence (2) | /home/frankie/projects/cvevidence-fresh | codex/frankie-fresh-milestones |
| 跨成員整合 | CVEvidence | /home/frankie/projects/cvevidence-integration | codex/integration-handoff |
| Horace 核心 | Horace 的開發環境 | 由 Horace 維護 | codex/horace-fresh-core |

兩個本機 checkout 已確認存在，協作訊息已送往整合 session；整合端確認前，不跨目錄修改或停止對方服務。

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

此檔中的檔案責任是已送出的協調提案，等待整合端確認；在確認前不並行修改共用檔案。

## 服務與資料隔離
目前 8505 仍由 fresh checkout 的 workspace_service 管理。
建議 8505 交整合端，Frankie 開發另用 8506；尚未接管前不停止或重啟 8505。
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
- catalog_entries 尚未支援新增 archive.repo_path，正式樣品尚需整合端接入選單。
- Q1–Q5／正式判定／AI 仍未有可整合交付；Horace 的 Live 試跑是他同步的進度，不是本工作台的驗收。
