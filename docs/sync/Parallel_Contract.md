# D 核心與前端資料介面驗收

2026-09-12 14:05（Asia/Taipei），首筆結果已完成，後續介面隔離驗收執行中。只修改本 worktree 的 QA 腳本及自己的兩份 MD。

- 固定核心：`44efc7bdcc533760ab167a2a005b0111b9758483`。
- renderer：`40802c865ee74046938d67b3b6f7715bdc3cb188`；report：`184145cc80fd145c47f1a4464538e05bca675d73`；integration：`a47a1a342ec86a9b6b26f9dedb318b6490250d28`。
- 入口實際為 `src/cvevidence_core/frankie_adapter.py:analyze_archive_for_runner`；此核心 SHA 沒有 `runner_adapter.py`。
- **PASS：今日 ROM 03 真 archive → OFFLINE 多 CVE JSON → 指定 renderer recording fake Streamlit 與報告**。3 個選取（Heartbleed、另一已知 CVE、未知 CVE）均無 renderer error／AI_SCOPE_MISMATCH；Heartbleed 為 NEEDS_INVESTIGATION、5 queries、8 evidence。尚非真實瀏覽器端到端。
- 靜態確認：integration worker 尚無 analyze 操作，`CoreService.collect_digest` 只保存 COLLECTED；contracts 的 engineering_status/ai_status 只接受 NOT_RUN。正式接線為 Frankie 責任，D 不改產品。
- **PASS：AI 不缺轉接身分**。真實 OFFLINE 回傳 `ai.cve_id=CVE-2014-0160`、`ai.engineering_assessment_id=A-45893395c61e816f7acb17afbeae75ad552e2a3652a3663de8e62dc781ff2d33`，context 與 assessment 全部一致，renderer/report 直接接受。請勿補造或覆寫這些核心欄位。
- **FAIL（靜態阻塞確認，Frankie）**：integration `src/cvevidence/core_worker.py:29-50` 沒有 analyze；`core_service.py:90-105` 只保存收件；`contracts.py:64-80` 缺 analyses/queries/AI investigation 保存且 engineering_status/ai_status 只接受 NOT_RUN，Condition 還是 TRUE/FALSE/UNKNOWN 而非 SUPPORTED/BLOCKED/UNKNOWN。需要正式分析保存契約及 worker 接線，D 不修改。
- **FAIL（原文 locator 呈現缺口，Frankie）**：真實 Heartbleed E-34b2e95… 的 `excerpts[0]` 含 X-ID、source/file hash、26–37 行與原文，但 renderer `analysis_view.py:95-104` 和報告 `analysis_report.py:24-27` 都只讀 witnesses，未呈現 excerpts。結果可以顯示；定位原文鏈仍不完整。補上讀取核心既有 excerpts 與同 run/context 來源工具連結即可，不能憑 witness 自造行號。
- 尚未找到 B 的 `var/validation/parallel-ai-r2`，Live 介面暫列 NOT_RUN，不等待、不打 API。
- 目前可用工具沒有跨對話傳訊能力；主對話 `01a09347-f3e1-77a3-b66f-f1f2877bef7a` 請讀此 MD 和本分支 commit。
- 原始輸出：本 worktree `var/validation/parallel-contract/`（Git ignored）；尚未執行同版 75 項／9 格回歸，依本輪指示聚焦新增介面風險。
- 實際命令：`python3 scripts/qa_contract/probe.py`；實驗耗時 2.334 秒，3 個真 JSON renderer/report 選取，並非 3 項 pytest。
- 首筆結果：`var/validation/parallel-contract/run-20260912T060439734452Z/summary.json`，同目錄保存 engineering.json、events.json、逐 CVE renderer call recording／文字報告、provenance。
- 核心可產出：PASS；renderer 基本單元介面相容：PASS；locator 完整呈現：FAIL；Runner 完整分析接線：FAIL（靜態）；真正 UI：NOT_RUN；Live：NOT_RUN。
