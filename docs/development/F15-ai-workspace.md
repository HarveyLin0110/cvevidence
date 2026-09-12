# F15：獨立 AI 調查與工作台接線
日期：2026-09-12。負責：Frankie；整合端已授權此 session 實作 AI 執行／保存，Horace 的判定規則不在修改範圍。

## 完成條件與交付
- 已保存且通過 scope/hash 核對的工程結果，才能建立独立 AIRequest/AIOutcome；工程 RunEnvelope 不變。
- Runner.investigate_ai/read_ai/ai_history/ai_configuration；UI 勾選本次外送授權後才呼叫。
- START/END 原子新建，同 ID 同輸入重送取得既有結果；並發或缺 END 不自動重跑。
- 可信任 worker 固定啟動、僅傳必要 AI 環境，重取證後呼叫 Horace investigate_after_engineering。
- 最長180秒（API可配置至300秒）的程序群組期限；核心原有90秒、8次模型上限不改。
- 結果、失敗、歷史與下載分開保存；報告以副本加入所選 AI，不覆写原工程結果。追加重判另列。
- schemas/ai-request.json、ai-outcome.json 可供其他開發者核對契約。

## 設定
在 WSL checkout 的 .env.local 填寫 OPENAI_API_KEY、OPENAI_MODEL、OPENAI_REASONING_EFFORT；chmod 600。不提交 Git。
使用專案 venv 執行 python scripts/start_local_ai.py，只重啟本 checkout 的8506。
正式多人站由部署負責人用 CVEVIDENCE_AI_ENABLED=1 與可信任 CVEVIDENCE_AI_ENV_FILE 配置；此交付不複製金鑰至公開站。
受限金鑰需 Responses API 權限。到期需更新本機設定，程式不自動續期。

## 驗收
tests/test_ai_attempts.py 的10項測試：缺配置/授權不呼叫、scope/竄改拒絕、原工程不變、同ID冪等/並發、缺END禁止重跑、timeout終止程序群組、環境不繼承GitHub/OAuth秘密、UI授權與報告副本。
模型收據單元測試使用TEST_ONLY；不宣稱是真實模型輸出。
實際 gpt-5.6-sol 最小非工程請求 HTTP200/completed，確認連線。
真實 CMake06 工程後 AI 嘗試 63302644-ac91-40c4-b6ba-687251993650 為 TIMED_OUT，原工程保持不變；不可將此列為LIVE成功。完整runtime留本機var。

## 安全規則與限制
對應 D01/D02/D05/D06/D07/D08/D09、R01/R03/R06/R07/R08/R09/R10/R11/R12。
沒有配置、未同意、失敗或超時不回退為OFFLINE成功；原有工程OFFLINE紀錄仍獨立存在。
呼叫收據/hash證明資料一致性，不等於來源認證或語意支持已驗證；subprocess非完整OS sandbox，未實作總記憶體/磁碟quota。
此迭代不修改Horace核心。新核心版本/公開站/完整LIVE閉環需另驗收並留下固定SHA。
