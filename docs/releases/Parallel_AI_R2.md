# Parallel AI 第二輪交件

固定核心基準：`44efc7bdcc533760ab167a2a005b0111b9758483`。分支：`codex/parallel-ai-validation-r2`。工作區：`/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/ai-validation-r2`。

**4 個整合案例：2 個模擬 PASS；2 個正式 Live 為 1 PASS、1 FAIL。** 真實 API 共 10 次，全部使用既有 `gpt-5.6-sol`／`medium`。第一筆 Live 的失敗完整保留，沒有用後續成功覆蓋。

歷史中性說明已不再觸發第一輪的 AI 入站相容問題。ROM 03 同 build 補件後，工程結果為 `NOT_AFFECTED`；歷史說明存於 `statement_context` 並保留原 material/context，`statement_reviews` 為空。成功 Live 的追加原文經再次核對後產生 1 筆 `SOURCE_OBSERVATION`，重判仍是 `NOT_AFFECTED`，歷史及已保存工程 dict／檔案 hash 完整不變。

## 交件與責任

- 首筆可測 QA commit：`383c9929587a55b2a37aecbf5d90b7dee9825b8e`。
- 最終 QA 程式 commit：`59b51c9a7279eea4eab66ad39545ae2d2b4e5bbb`。其後僅補本報告與自己的同步紀錄；文件 commit 在交件訊息另列。
- 改動：`scripts/validate_ai_reliability.py`、`docs/sync/Parallel_AI.md`、本報告。沒有修改產品 src、contracts、UI、Runner、報告產品或其他人的同步檔。
- 本輪未修改 `tests/test_ai_reliability.py`；直接執行以下 4 個真包整合案例，沒有重跑同版本 75 項既有單元測試、CMake/curl Live。
- QA 新增 `r2-mock`／`r2-live`。第二筆 Live 使用 `--r2-from-run` 唯讀重用本工作區已保存快照，不重做 ROM 補件；每次輸出另建 run。
- 未合入主線、推送或部署。沒有可呼叫的 `send_message_to_thread`；主對話與 D 可直接讀以下 MD、commit 與 JSON。

## 實際執行

以下 cwd 均為本工作區。第一、二個命令獨立執行，第三個是第二個、也是最後一個 Live 情境。

```bash
python3 scripts/validate_ai_reliability.py --mode r2-mock
python3 scripts/validate_ai_reliability.py --mode r2-live --env-file /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/.env.local
python3 scripts/validate_ai_reliability.py --mode r2-live --env-file /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/.env.local --r2-from-run var/validation/parallel-ai-r2/20260912T060523891384-r2-live-3f42af5f --r2-question '請直接讀取已提交的 build/commands/0014-extracted-device-tcp-normal-run.log 原文，必要時再看同名 json 的執行紀錄。只核對這次正常 TCP/TLS 測試能證明什麼，以及為何不能單靠正常測試推定 Heartbleed 已重現或實際部署安全。完成這一項追加調查即可；工程判定已由同 build 證據作成。'
git diff --check
git diff --exit-code 44efc7bdcc533760ab167a2a005b0111b9758483 -- src contracts
```

只由受信任設定讀取器使用 `.env.local`，沒有回顯、複製、提交 key 或修改設定。Git 只在命令當次使用 `Codex <codex@localhost>` 作者識別。

## 實測結果

| 案例 | QA | AI 狀態 | 真實 API／模擬呼叫 | AI 秒／入口秒 | 工程保留 | 重判 |
| --- | --- | --- | --- | --- | --- | --- |
| ROM 補件＋歷史中性＋timeout | PASS，12 項檢查 | TIMED_OUT | 0／2 | 3.166／11.637 | PASS | NOT_RUN，符合失敗處理 |
| ROM 補件＋歷史中性＋無效引用終止 | PASS，13 項檢查 | INVALID_CITATION | 0／3 | 7.170／14.172 | PASS | NOT_RUN，符合失敗處理 |
| Live：heartbeat 函式與 dispatch 排除一致性 | FAIL | BUDGET_EXHAUSTED | 8／0 | 73.196／82.594 | PASS | NOT_RUN，未完成 AI |
| Live：正常 TCP/TLS 原文的證明邊界 | PASS，15 項檢查 | COMPLETED | 2／0 | 16.519／34.383 | PASS | PASS |

Mock run 含解包、補件與工程取證共 76.107 秒；第一筆 Live run 共 130.660 秒；重用快照的第二筆 Live run 共 43.712 秒。這些 run 部分平行執行，不可相加當實際牆鐘總耗時。延後 AI 入口本身採既有 **8 次工具／90 秒**預算；整體 run 還包含本機取證、完整性掃描與重判。

共同準備的 9 項檢查涵蓋：缺件時 Needs Investigation、同 build 補件後 Not Affected、成品及 build 不變、新快照 context、原聲明 material/source context 保留、新 assessed context 及中性說明不阻擋 verdict。

模擬案例先完成 READ 再注入失敗：timeout 留下第二次呼叫錯誤；無效引用在原有一次更正後仍錯誤時終止，保留兩笔 `REJECTED`。兩案的工程 dict 與保存檔案 hash 不變，已完成 READ 不消失，失敗沒有被升格成追加工程條件。實際 API 呼叫 0，內層 AI `mode=SIMULATED`；原始 workflow 外層 mode 固定是 LIVE，因此 QA wrapper 額外標 `MOCK_TRANSPORT`／`formal_live_eligible=false`，不混算正式 Live。

第二筆 Live 讀取正常連線日誌四行原文，正確保留 loopback、TLSv1.2、正常收發與未送攻擊 payload 的限制。摘要沒有把正常測試當成 Heartbleed 重現或部署安全。完成引用經未修改的 Verifier 重新核對；新增觀測 `condition_inference_verified=false`，自由文字沒有改變正式條件。

## 給主對話的待修風險：ROM 廣範圍調查耗盡工具預算

最小重現：固定本報告基準，執行第二個命令（預設 `r2-live` 問題為核對同 ROM 的 heartbeat 函式與 TLS record dispatch 排除是否一致，並區分部署暴露）。此結果受模型取樣影響，不保證每次相同工具順序。

- 預期：使用同 build 已有來源，在預算內完成追加調查，接續原文核對與重判。
- 實際：`LIST → LIST → SEARCH → LIST → LIST → SEARCH → COMPARE(TOOL_ERROR) → COMPARE`，8 次／73.196 秒後 `BUDGET_EXHAUSTED`，沒有 COMPLETE。第七次把四個 source IDs 送入 COMPARE；收到「需要兩個」後，第八次改為兩個並成功。
- 所有工程輸入仍保留、無效參數仍拒收。`workflow.py:57` 在 AI 未完成時跳過重判符合目前約定，不能把這筆記成重判成功。
- 責任範圍：主對話／AI 工具規劃。參考 `src/cvevidence_core/ai.py:182`（COMPARE 參數個數）、`:202`（工具錯誤回饋）、`:208`（預算耗盡）。可評估把 READ／COMPARE 個數限制明示於工具引導，並向模型回傳剩餘工具預算，讓它保留必要的結論或補件步驟。不要放寬 Verifier 或把未完成狀態改成功。
- 本輪未修改產品程式；此風險仍待主對話評估／修正。

首版 QA 曾只把 READ 視為新增原文；第一筆 Live 實際以 SEARCH 保存兩筆原文。QA 已接受 READ 或 SEARCH，不要求固定工具顺序。原始 summary 原封保留，另存 `qa-review.json` 註明這項計數修正；整體 Live FAIL 沒有改成 PASS。

## 主對話與 D 可讀的 JSON

所有路徑相對本工作區，只存在忽略的 `var/validation/parallel-ai-r2/`，沒有把原始輸出或解包資料加入 Git。

- `20260912T060516180542-r2-mock-b924ca36/`：`summary.json`；兩個子目錄 `timeout/`、`invalid-citation/` 各有 `ai-record.json`、`later-result.json`、`engineering-after-ai.json`、`citation-rechecks.json`、`events.json`、`reassessment.json`（null）。根目錄保存 `engineering-before-supplement.json`、`engineering-saved.json`、`engineering-readiness.json`、`supplement-plan.json`。
- `20260912T060523891384-r2-live-3f42af5f/`：第一筆失敗 Live 的同等完整紀錄；另有 `qa-review.json`。後續成功不覆寫此目錄。
- `20260912T060851113341-r2-live-923b8523/`：成功 Live 的 `live/later-result.json`、`live/ai-record.json`、`live/reassessment.json`、`live/engineering-after-ai.json`、`live/citation-rechecks.json`、`live/events.json`、`live/request-context.json`；根目錄有 `engineering-saved.json`、`reused-snapshot.json`、`semantic-review.json`、`handoff-index.json`。

`handoff-index.json` 提供三个 run 的絕對路徑及 PASS／FAIL 分類。NOT_RUN 範圍：既有 75 項全套、CMake/curl Live 重跑、Runner／UI／報告／部署，以及第一筆失敗 Live 後的重判。引用精確有效仍需要工程師覆核語意；兩筆 Live 不代表成功率保證。
