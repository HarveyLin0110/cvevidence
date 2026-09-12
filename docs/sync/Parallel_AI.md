# 平行任務 B：AI 調查可靠性

## 第二輪正在執行：合併後 ROM Live 與工程結果保留

- 固定核心基準：`44efc7bdcc533760ab167a2a005b0111b9758483`；已核對 HEAD 與分支。
- 本輪工作區：`/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/ai-validation-r2`；分支 `codex/parallel-ai-validation-r2`。
- 狀態：RUNNING。只新增／修改分配的 QA 腳本、測試、本同步檔與 `docs/releases/Parallel_AI_R2.md`，不修改產品程式。
- 目標：ROM 03 同 build 補件後，攜帶歷史中性聲明，走 `investigate_after_engineering`，保留正式工程 dict 並驗證追加原文／重判；另做明確模擬的 timeout、無效引用終止。
- 最新程式讀取結果：中性說明目前保存在 `statement_context`，不是 `statement_reviews`；第一輪「中性聲明將被 AI 入站拒絕」警示不能沿用，待本輪實測。
- 首筆結果：PASS，ROM 補件完成後 `NOT_AFFECTED`，9 項工程／歷史綁定檢查全部通過；保留舊 context 的中性聲明且 statement_reviews 為空，已經通過 OFFLINE 的 AI 入站檢查。模擬 timeout、無效引用終止兩案已 PASS（25 項檢查）；第一個 Live FAIL：8 次 API／73.196 秒 AI，BUDGET_EXHAUSTED；正式工程 dict／已保存 JSON 均未變。原文 SEARCH 已取得、一次 COMPARE 用四個來源被 TOOL_ERROR 後修正，但沒有預算 COMPLETE；重判 NOT_RUN。
- 首筆 JSON：`var/validation/parallel-ai-r2/20260912T060516180542-r2-mock-b924ca36/engineering-readiness.json`、同目錄 `engineering-saved.json`。Live run：`20260912T060523891384-r2-live-3f42af5f`。
- 第一筆 Live 風險最小重現：上述 r2-live 命令，固定 8 次／90 秒。預期完成調查後重新核對原文並重判；實際工具順序 LIST、LIST、SEARCH、LIST、LIST、SEARCH、COMPARE(TOOL_ERROR)、COMPARE，未送出 COMPLETE。產品責任：AI 工具參數引導與剩餘預算收尾（`src/cvevidence_core/ai.py:182`、`:202`、`:208`）；`workflow.py:57` 正確跳過失败重判。本輪不改產品程式。
- QA 也修正「只接受 READ 當原文」的檢查以接受 SEARCH matches；第一筆 Live 原始摘要保留不覆寫，另以閱讀核對註記其 SEARCH 原文確實保留。
- 第二個且最後一個 Live 將聚焦同 ROM 的正常 TCP/TLS 原文；重用本輪已保存快照與工程 JSON，輸出另建 run，不重做補件工程驗證。
- Mock 實測：總耗時 76.107 秒（含 ROM 解包／同 build 補件及前後工程取證）；timeout 案入口 11.637 秒、invalid-citation 案入口 14.172 秒。實際 API 0 次，模擬 transport 2／3 次。工程 dict 與已保存 JSON hash 均未變，先前 READ 保留，失敗不重判；無效引用兩次拒收均留下。
- 首個 QA commit：`383c9929587a55b2a37aecbf5d90b7dee9825b8e`。
- 已執行：`python3 scripts/validate_ai_reliability.py --mode r2-mock`；`python3 scripts/validate_ai_reliability.py --mode r2-live --env-file /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/.env.local`。不重跑已通過的 CMake／curl 或 75 項全套。
- 本對話仍沒有 `send_message_to_thread` 工具；主對話可直接讀本 MD／commit。

---

以下為第一輪歷史紀錄，不代表本輪最新整合狀態。

## 範圍與基準

- 主對話：比賽進行時，`01a09347-f3e1-77a3-b66f-f1f2877bef7a`，唯一負責主線整合。
- 基準：`b89059fdd1f751b43559187fd488844c9eeb3336`。
- 分支：`codex/parallel-ai-reliability`。
- 工作區：`/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/ai-reliability`。
- 只修改 `src/cvevidence_core/ai.py`、`tests/test_ai_reliability.py`、`scripts/validate_ai_reliability.py`、本檔；未改 Verifier、來源、判定規則、workflow、Runner、UI 或既有 Live 驗證器。
- 本對話沒有可呼叫的 `send_message_to_thread` 工具；此檔與交件摘要供協調／主對話讀取，未宣稱已發送訊息。

## 交件內容

沿用既有一次引用更正機制，沒有增加重試上限。新增：

- `calls` 在送出 request 前建立；`errors` 記錄失敗階段、呼叫序號與代碼。HTTP 狀態碼可見，不保存設定或 HTTP headers。
- 格式錯誤及不合法工具參數保留在呼叫紀錄；逾時、API 失敗或來源錯誤不清除已完成的工具結果與工程 assessment。
- 重新計算剩餘時間，遲到回應不能完成；更正仍消耗原本工具與時間預算。
- curl 調查的具體短／長開關須逐字存在於模型已看過的可核對原文或有原文支持的初始工程事實。不存在的開關保留為 REJECTED，附明確錯誤後允許原有一次更正。這是字面來源核對，不是 curl 命令語意解析或新漏洞判定器。
- 提示模型優先 READ 已提交的 launcher/config/觀測，只要求仍缺少的觀測或綁定依據。
- 新驗證器分 `mock`、`live`、`live-fault`。最後一種每次都呼叫真實 API，僅首次工具提案引用由測試程式破壞；依既有 API 標為 SIMULATED，明確不計正式 Live。

## 交件 commit

- 第一個可測 commit：`ea7245b9ab3a91a5756b3fd58d7702bc02c7a371`。
- 最終程式交件 commit：`d79143203fb6f35311dc6ff09b0ca554105e8859`（在上一個 commit 上追加來源發現提示與工具錯誤邊界）。
- 本文件的最後紀錄 commit 在交件訊息另列；整合時取本分支基準之後的三個 commit，或檢閱整個基準至分支 HEAD 差異。
- Git 未設定作者；提交只使用命令當次的 `Codex <codex@localhost>`，未變更任何 Git／環境設定。

## 實測指令與結果

所有下列命令的 cwd 都是上述指定工作區。

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/validate_ai_reliability.py --mode mock
python3 scripts/validate_ai_reliability.py --mode live --env-file /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/.env.local --max-calls 8 --timeout-seconds 90
python3 scripts/validate_ai_reliability.py --mode live-fault --case early --env-file /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/.env.local --max-calls 8 --timeout-seconds 90
python3 scripts/validate_ai_reliability.py --mode live --case missing --env-file /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/.env.local --max-calls 8 --timeout-seconds 90
git diff --check
```

- 基準原有 31 項通過；第一個 checkpoint 為 51 項；最終 **54 項通過（原有 31、新增 23）**。
- 新增 mock 測試涵蓋引用恢復／再次失敗拒收、剩餘工具／時間預算、hash 更正、空白與錯誤參數、無效 API envelope、缺 call_id、來源與 I/O 失敗、429、timeout／connection、工程結果保留、curl 開關原文與 API 名稱不能變 CLI。
- 最終 mock 驗證器：23 項通過，0 API 呼叫。原始輸出在 `var/validation/parallel-ai/20260912T054856031709-mock-cca84eb8/`。早期 20 項紀錄另保留於 `20260912T054544142141-mock-55e1cfc9/`。
- Live 均使用既有 `gpt-5.6-sol` / `medium`，不回顯、不複製 key。最多 8 次 request、90 秒調查預算；本輪實際共 18 次 API 呼叫（正式 Live 12、故障注入 6）。

| 種類／情境 | 結果 | API 次數 | AI 秒數 | 閱讀核對 |
| --- | --- | ---: | ---: | --- |
| 正式 Live／缺資料，首次 | NEEDS_USER_INPUT | 4 | 39.320 | 傳輸／引用有效；發現 SEARCH 內容不應代替 LIST 檔名，已修正並保留原紀錄 |
| 正式 Live／提前完整提供 | COMPLETED | 4 | 32.681 | READ launcher、config、觀測；沒有 ASK_USER，區分受影響條件與尚未重現漏洞 |
| 真實 API 故障注入／無效引用 | COMPLETED；保留 1 筆 REJECTED | 6 | 48.670 | 明確錯誤後重新 READ，修正引用再完成；**mode=SIMULATED，不計正式 Live** |
| 正式 Live／缺資料，修正後重驗 | NEEDS_USER_INPUT | 4 | 28.597 | 限定檔名 LIST，再 READ build 紀錄；索取實際缺少的 launcher/config/啟動綁定 |

正式 Live 的兩個目標情境已通過；完整資料與故障注入使用第一個 checkpoint，後續只重驗受來源發現提示影響的缺件情境，未反覆重跑已成功案例。所有 accepted 引用核對有效、工程 assessment 未變；引文一致仍不等於工程師簽核語意。

每次結果均獨立存放，未覆寫舊 run：

- `var/validation/parallel-ai/20260912T054557376938-live-f2cad58e/`：首次缺資料、提前完整提供。
- `var/validation/parallel-ai/20260912T054557474524-live-fault-5c3b0700/`：故障注入，另存注入前後 arguments 與真實 API response IDs。
- `var/validation/parallel-ai/20260912T054906677270-live-1202c130/`：缺資料修正後重驗。

每個 Live 目錄有 `summary.json`、逐案 `result.json` 與閱讀核對的 `semantic-review.json`。原始紀錄及解包資料僅存在本工作區忽略的 `var/validation/parallel-ai/`，沒有加入 Git，也沒有重建 demo。

## 限制與整合提醒

- 引用存在／原文一致不等於語意推論正確，維持 `meaning_verified=false`。
- 來源優先與避免重複索件需要人工核對 Live 問題與原文，不能只看 transport gate。
- API timeout 與每次迴圈檢查提供有界預算；既有本機完整性掃描與同步 I/O 不是硬即時取消。遲到回應不接受為完成，已取得結果保留。
- 【第一輪歷史風險；第二輪已發現中性聲明改存 statement_context，正在實測確認】未修改 assessment 的既有聲明判定相容檢查：`ai.investigate` 仍以「有 statement_reviews → NEEDS_INVESTIGATION」驗證輸入；若 A 分支允許中性聲明保留原 verdict，主對話必須協調這個既有入口條件，否则會在 AI 開始前拋 IntegrityError。此項屬 A/B 整合，尚未在本分支聲稱完成。
- 本分支提交只代表可供主對話整合，未合入主線、未推送或部署。
