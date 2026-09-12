# F14b 唯讀分析畫面交付

2026-09-12；基於 Horace d8d75ba 的 workflow、assessment、evidence、AI 回傳欄位實作。整合端明確同意先做獨立 renderer；本批不接 workspace、不改 RunEnvelope／worker，也不觸碰 team_app。

## 呼叫介面

`render_analysis(st, payload, *, context_hash, cve_id, key, on_report=None, on_supplement=None)`

- payload：由呼叫端讀回、已通過正式保存驗證及帳號授權的核心 JSON，包含 context_hash、analyses 陣列。
- context_hash／cve_id：來自選定的 run，不由模型提供。只能匹配一個 analyses entry；assessment 若存在也必須匹配 scope。
- key：呼叫端提供的元件唯一 key；建議使用 run ID。
- on_report／on_supplement：呼叫端提供不帶參數的導覽 callback；未接時停用按鈕並說明，接入後兩者皆須可達。
- entry 使用 queries／evidence／assessment／ai。缺少可選欄位顯示未提供，不從其他案件補值。Q1–Q5 固定列出，PC 分組未確認因此不猜。
- ai 必須匹配 context_hash、cve_id、engineering_assessment_id；不符只拒絕 AI 畫面，保留工程結果。
- 獨立 AI 保存紀錄的拼接仍由正式 adapter 決定；本元件不修改工程 dict，也不自行載入 AI 歷史。

UI 不執行分析、不重新計算 verdict、不取代 verifier。scope 比對只是避免選错結果的顯示防護，不代表引用／資料完整性已經驗證。

## 行為及安全規則

工程判定、五項 query、條件、原值／來源、衝突、人工聲明及缺件分區。AI mode/status、動態問題、目的、動作、結果與模型呼叫分開顯示。被拒提案不顯示其 finding／required_files 為有效建議。資料內容使用 st.text／st.code，不將外部 Markdown、HTML 或 URL 當成動作。

對應 D01/D02/D07/D08/D09、R01/R05/R06/R07/R08/R11/R12；遵循 F14 提案的工程先保存與 AI 失敗仍有出口。獨立 AI timeout／預算實際執行仍由整合端負責，沒有新增 runtime 安全保證。

## 測試

73 pytest passed；新測試5項：跨 scope／重複 CVE 拒絕、AI timeout 保留工程與兩個出口、未知 CVE、AI 父判定不符、外部 HTML/Markdown 安全文字及拒絕提案不當建議。測試資料全部 TEST_ONLY，不算真實漏洞、引用語意或 LIVE 模型驗收。

待完成：正式保存欄位與獨立 AI API、workspace 實際接線、實包畫面與補件閉環。此批可獨立審查；沒有宣稱本機正式工作台已顯示完整分析。
