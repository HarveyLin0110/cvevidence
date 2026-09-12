# 平行任務 B：AI 調查可靠性

## 範圍與基準

- 主對話：比賽進行時，`01a09347-f3e1-77a3-b66f-f1f2877bef7a`，唯一負責主線整合。
- 基準：`b89059fdd1f751b43559187fd488844c9eeb3336`。
- 分支：`codex/parallel-ai-reliability`。
- 工作區：`/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/ai-reliability`。
- 只修改 `src/cvevidence_core/ai.py`、`tests/test_ai_reliability.py`、`scripts/validate_ai_reliability.py`、本檔；未改 Verifier、來源、判定規則、workflow、Runner、UI 或既有 Live 驗證器。
- 本對話沒有可呼叫的 `send_message_to_thread` 工具；此檔與交件摘要供協調／主對話讀取，未宣稱已發送訊息。

## 第一個可測 checkpoint

沿用既有一次引用更正機制，沒有增加重試上限。新增：

- `calls` 在送出 request 前建立；`errors` 記錄失敗階段、呼叫序號與代碼。HTTP 狀態碼可見，不保存設定或 HTTP headers。
- 格式錯誤及不合法工具參數保留在呼叫紀錄；逾時、API 失敗或來源錯誤不清除已完成的工具結果與工程 assessment。
- 重新計算剩餘時間，遲到回應不能完成；更正仍消耗原本工具與時間預算。
- curl 調查的具體短／長開關須逐字存在於模型已看過的可核對原文或有原文支持的初始工程事實。不存在的開關保留為 REJECTED，附明確錯誤後允許原有一次更正。這是字面來源核對，不是 curl 命令語意解析或新漏洞判定器。
- 提示模型優先 READ 已提交的 launcher/config/觀測，只要求仍缺少的觀測或綁定依據。
- 新驗證器分 `mock`、`live`、`live-fault`。最後一種每次都呼叫真實 API，僅首次工具提案引用由測試程式破壞；依既有 API 標為 SIMULATED，明確不計正式 Live。

## 驗證

所有下列命令的 cwd 都是上述指定工作區。

- 修改前：`PYTHONPATH=src python3 -m unittest discover -s tests -v`，原有 31 項通過。
- 修改後：相同命令，51 項通過（原有 31、新增 20）。
- `python3 scripts/validate_ai_reliability.py --mode mock`：20 項通過、API 呼叫 0。
- Mock 結果：`var/validation/parallel-ai/20260912T054544142141-mock-55e1cfc9/`。
- 正式 Live 與真實 API 故障注入已啟動，尚未在此 checkpoint 宣稱通過；結果補在下一個紀錄 commit。

## 限制與整合提醒

- 引用存在／原文一致不等於語意推論正確，維持 `meaning_verified=false`。
- 來源優先與避免重複索件需要人工核對 Live 問題與原文，不能只看 transport gate。
- API timeout 與每次迴圈檢查提供有界預算；既有本機完整性掃描與同步 I/O 不是硬即時取消。
- 未修改 assessment 的既有聲明判定相容檢查；若 A 分支改動聲明 verdict，主對話應協調該既有入口條件。
- 本分支提交只代表可供主對話整合，未合入主線、未推送或部署。
