# D 核心與前端資料介面驗收

2026-09-12 14:12（Asia/Taipei）。第二輪指定範圍完成，產品缺口交回負責者。詳見 `docs/releases/Parallel_Contract.md`。

工作區：`/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/contract-qa`；分支：`codex/parallel-contract-qa`。只提交 `scripts/qa_contract/`、`tests/qa_contract/` 及自己的兩份 MD；沒有修改產品、主 checkout、服務或他人同步檔。

| 元件 | 固定 SHA |
| --- | --- |
| 核心 | `44efc7bdcc533760ab167a2a005b0111b9758483` |
| renderer | `40802c865ee74046938d67b3b6f7715bdc3cb188` |
| report | `184145cc80fd145c47f1a4464538e05bca675d73` |
| integration | `a47a1a342ec86a9b6b26f9dedb318b6490250d28` |

首筆結果於 14:05 寫入，checkpoint commit `4f67f8d`。真 ROM 03 → 多 CVE renderer/report：2.334 秒，3 個選取，無 scope error。Heartbleed：NEEDS_INVESTIGATION、5 queries、8 evidence。核心入口實際為 `frankie_adapter.py:33`，沒有 `runner_adapter.py`。

| 驗收面向 | 結果 |
| --- | --- |
| 核心真 archive 產出、多 CVE、未知 CVE | PASS |
| renderer/report 基本資料與 AI 身分相容 | PASS；核心已有 cve_id、engineering_assessment_id，不需補造 |
| context/CVE/assessment 隔離、補件前後比較 | PASS；唯讀複用 B 已完成真工程結果 |
| 原文 X-ID/locator 呈現 | FAIL；兩個 consumer 都省略 evidence.excerpts |
| 指定 Runner 收件與保存 | PASS；COLLECTED、432 sources、assessment=null |
| 指定 Runner 完整分析接線 | FAIL；工程/AI 仍 NOT_RUN，analyze 被拒絕，六類直接映射被舊契約拒絕 |
| 延後 AI 失敗狀態的 consumer 介面 | PASS；3 情境、30/30 檢查；僅 QA 投影，正式 Runner 未接 |
| B 首筆 Live 完成調查/重判 | FAIL/NOT_RUN；8 次 API 後 BUDGET_EXHAUSTED，followup=null |
| 真實 UI/瀏覽器端到端 | NOT_RUN；僅 recording fake Streamlit |

**Frankie 優先處理**：integration `core_worker.py:29-50`、`core_service.py:90-105`、`contracts.py:48-80` 的完整分析入口與保存形狀；舊版只含單 CVE/NOT_RUN，不能直接塞核心 analyses/條件/E-ID/AI。再补 `analysis_view.py:90-98`、`analysis_report.py:25-28` 對 excerpts 的原文定位呈現。D 提供真實失敗測試，沒有改產品。

**延後 AI 接線**：`investigate_after_engineering` 回傳是 AI stage wrapper，不能取代完整 engineering JSON。核對 context、CVE、外層及內層 engineering_assessment_id，再將 ai/investigation_verification 掛回對應 analyses 項，保留工程 assessment。核心三個 AI 身分欄位均存在，不可覆寫 ID 來通過 guard。

**版本風險**：a47a1a3 來源工具和 44efc7b 的 X-ID hash 定義不同。同 context/source/26–37 行/bytes，舊工具回 X-890328…，新核心為 X-9d2a37…。正式整合需統一分析與來源工具的核心版本。本輪 Runner 使用 a47a1a3 完整 src，沒有混版冒稱正式版本。

真正執行：

- `python3 scripts/qa_contract/probe.py`：1 真 archive、3 CVE consumer 選取，2.334 秒。
- `var/validation/parallel-contract/qa-venv/bin/python scripts/qa_contract/integration_probe.py --engineering var/validation/parallel-contract/run-20260912T060439734452Z/engineering.json`：1 真 Runner 收件/保存/來源、analyze 拒絕、6 類契約診斷，3.451 秒。
- `var/validation/parallel-contract/qa-venv/bin/python scripts/qa_contract/acceptance.py --engineering var/validation/parallel-contract/run-20260912T060439734452Z/engineering.json --b-run /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/ai-validation-r2/var/validation/parallel-ai-r2/20260912T060516180542-r2-mock-b924ca36`：16 pytest，14 PASS/2 FAIL，0.296 秒。兩 FAIL 為 locator 缺口。
- `python3 scripts/qa_contract/later_ai_probe.py --b-run /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/ai-validation-r2/var/validation/parallel-ai-r2/20260912T060516180542-r2-mock-b924ca36 --b-run /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/ai-validation-r2/var/validation/parallel-ai-r2/20260912T060523891384-r2-live-3f42af5f`：30/30 介面檢查，0.248 秒；D API 呼叫為 0。

結果根目錄：本 worktree `var/validation/parallel-contract/`（ignored）。四個 run：`run-20260912T060439734452Z`、`integration-20260912T060658296068Z`、`acceptance-20260912T060842877733Z`、`later-ai-20260912T060953813116Z`。含原始 JSON、renderer recording、報告、JUnit/provenance；未把原始結果提交。

未重跑 75 項、9 格、CMake Live、C 的補件規則/錯誤邊界。沒有可用的跨對話傳訊工具；未宣稱已通知主對話 `01a09347-f3e1-77a3-b66f-f1f2877bef7a`，請讀本 MD/commit。
