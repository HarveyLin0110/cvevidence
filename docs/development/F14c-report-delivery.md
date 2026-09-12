# F14c 工程報告與補件比較交付

2026-09-12；獨立於正式保存介面的純函式，接續 F14b 40802c8。

## 介面

- `export_analysis(payload, *, context_hash, cve_id, run_id)`：回傳 UTF-8 文字報告，呼叫端以 text/plain 下載。固定選取一個 CVE；內容包含 Q1–Q5、條件、原值、來源、缺件、範圍及獨立 AI 狀態。AI scope 不符則省略該 AI 內容；未完成／被拒提案不列有效調查結果。此匯出不重新驗證原文。
- `compare_analyses(parent, child, *, parent_context, child_context, cve_id)`：回傳同產品／release／build／成品 hash 的條件明細差異與前後 verdict。缺少身分、跨 build 或重複 condition_id 拒絕。即使 verdict 相同，證據差異仍可呈現。
- 呼叫端必須使用已授權且通過正式保存驗證的結果，並核對 child.parent_run_id 等 lineage；此函式不載入磁碟、不授權帳號、不驗證 parent 關係或來源真實性。
- 不修改既有 reports.py 或 workspace，待整合端正式欄位交付後連接下載及比較。

## 驗收

81 pytest passed；本批8個參數化案例涵蓋 AI timeout 報告、跨 AI scope、拒絕提案、同判定不同證據、產品／release／build／artifact 不同或缺失、重複條件。全為 TEST_ONLY 顯示資料，不算真實漏洞及同 build 補件驗收。

對應 D01/D02/D07/D08/D09、R01/R05/R06/R07/R08/R11/R12。報告只描述核心保存结果；不以 AI 文字覆蓋工程判定，不由前後差異推論因果，不把 hash 當來源認證。
