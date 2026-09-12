# D 第二輪核心／前端資料介面驗收交件

2026-09-12，14:14 Asia/Taipei。**真實核心 JSON 可被指定 renderer／報告基本接受；指定 integration 的分析／保存接線仍阻止第一筆網頁完整工程結果。原文 locator 呈現另有兩個可重現失敗。** 本輪不是瀏覽器端到端，不能據此宣稱網頁可 demo。

## 固定版本與來源

| 元件 | SHA |
| --- | --- |
| 核心及今日 demo-inputs | `44efc7bdcc533760ab167a2a005b0111b9758483` |
| renderer | `40802c865ee74046938d67b3b6f7715bdc3cb188` |
| analysis report | `184145cc80fd145c47f1a4464538e05bca675d73` |
| Runner／worker／保存契約 | `a47a1a342ec86a9b6b26f9dedb318b6490250d28` |
| QA 首筆 checkpoint | `4f67f8d`；本分支後續小 commit 提供完整交件 |

工作區 `/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/contract-qa`，分支 `codex/parallel-contract-qa`。只修改自己的 QA 與兩份 MD，未修改產品 src、contracts、前端、Runner、保存、報告、主 checkout、服務或其他同步檔，未推送／合併。

先用 `git ls-tree` 找到 `src/cvevidence/analysis_view.py`、`analysis_report.py`，再由 `git show` 取至自己的 ignored scratch。Report 的 `.analysis_view` import 取自 report 自己的 SHA，並核對它與指定 renderer bytes 相同，SHA256：`ea20392a3863a0326920afe09cd460d710c29e788d60bb6f95a12de40b54fad3`。Runner 則以 `git archive a47a1a3 src requirements.txt` 的完整來源樹執行，包括該版自己的舊核心，沒有混用模組冒稱單一正式版本。

輸入為今日 `demo-inputs/rom/03_rom.tar.gz`，archive SHA256 `51a6edc8beb71530761eb486fba6f4c5cda029f65d12ed36c8a5a81dcf2bd7e0`。真實回傳：

- context：`362de586a0b4155ecfb281efd23d1571cfc6e4156833f910dc1ada01fa0d1726`。
- Heartbleed assessment：`A-45893395c61e816f7acb17afbeae75ad552e2a3652a3663de8e62dc781ff2d33`，NEEDS_INVESTIGATION，5 queries／8 evidence。
- 同一 archive 要求 Heartbleed、CVE-2022-37434、CVE-2099-99999；前兩者各自 NEEDS_INVESTIGATION，未知 CVE 為 UNSUPPORTED_CVE 且 assessment/ai=null。這是 ROM 多 CVE 介面驗收，不宣稱另一種交付格式也驗過。
- 實際核心入口為 `src/cvevidence_core/frankie_adapter.py:33`，該核心 SHA 沒有 `runner_adapter.py`。

## 結果分層

| 面向 | 結果 | 證據與限制 |
| --- | --- | --- |
| 核心可產出 | PASS | 真 archive，未人工拼成功 payload |
| renderer／report 基本相容 | PASS | 真 JSON，三個 CVE，無 AI scope error；recording fake Streamlit |
| context/CVE/A-ID 與補件隔離 | PASS | 16 項測試中的 14 項通過；錯 scope 拒絕，保留工程 |
| 原文 locator 呈現 | FAIL | 2 項 pytest 失敗，兩個 consumer 都省略 excerpts |
| 指定 Runner 收件／來源／保存 | PASS | COLLECTED、432 sources、保存再讀一致 |
| 指定 Runner 完整分析接線 | FAIL | assessment=null，工程/AI=NOT_RUN，analyze 操作被拒絕 |
| 延後 AI 失敗狀態的顯示介面 | PASS | 3 情境、30/30 檢查；僅 QA 投影，正式 Runner 未接 |
| B 首筆真實 Live 完成調查 | FAIL（引用 B 結果） | 8 次 API，BUDGET_EXHAUSTED；D API=0 |
| AI 新 evidence／成功重判呈現 | NOT_RUN | 已取得紀錄的 investigation_verification 均 null |
| 真實 UI、按鈕、正式 worker→UI 全鏈 | NOT_RUN | 未執行瀏覽器或真工作台操作 |

## 需要修正的介面缺口

### P1：Runner 仍只產出收件結果

責任：Frankie 的 worker、契約與保存接線。D 不改產品。

最小重現為對真 ROM 03 執行指定 integration 的 `Runner(RunStore(qa_store)).start_file(..., cve='CVE-2014-0160')`，再讀回已保存 run。第一筆完整工程畫面需要 analyses、queries、assessment 與独立 AI 狀態；實際為 COLLECTED、432 sources、assessment=null、engineering_status=ai_status=NOT_RUN。這是該版明確保留的收件範圍，尚未完成全分析接線。

- `a47a1a3:src/cvevidence/core_worker.py:29-50`：僅 collect/list/search/excerpt/compare/delta；實際 invoke('analyze', ...) 回 `Core rejected archive, context or operation`。
- `a47a1a3:src/cvevidence/core_service.py:90-105`：collect_digest 只建立收件 RunEnvelope；`:124` 收件，`:129` 保存。
- `a47a1a3:src/cvevidence/contracts.py:48-80`：條件 state 為 TRUE/FALSE/UNKNOWN；單一 cve_id；工程/AI 只接受 NOT_RUN；沒有 analyses 欄位。
- `a47a1a3:src/cvevidence/storage.py:64-67`：保存重新驗證模型，不能靠附加屬性繞過契約。

`integration_probe.py` 用真回傳驗六類直接映射：engineering_status、ai_status、analyses、core assessment、core evidence、core ai，全部被舊型別拒絕；完整 loc/type/msg 保存於 `direct-mapping-errors.json`。這是缺正式映射／保存形狀的證據，並非假定不同契約應能直接替換。

最小建議：由正式 Runner 呼叫既有 `analyze_archive_for_runner`，保存完整且受驗證的核心 payload 與 run/context 身分；保留 analyses[]，不要把工程 E-ID 壓成舊 source_file EvidenceRecord。完成保存後，renderer 以 context_hash+CVE 選取。工程完成與 AI 失敗要各自保存原狀態。

### P2：核心已有原文定位，兩個 consumer 均省略

責任：Frankie renderer／報告。

真 Heartbleed `E-34b2e95e7327a718818d3c2759eb63815a1cb421b9da5837dda3d1686a468cd4` 的 `excerpts[0]` 含：`X-9d2a37a057d8b87a89828de6`、`S-35ed00ab849c280932438f6a`、`source/device.c` 第 26–37 行、file_sha256、context_hash、完整 text。

預期工程師可從證據看到保存的原文定位，再以同 run/context 工具重核。實際 renderer `40802c8:src/cvevidence/analysis_view.py:90-98` 只讀 value/reason/witnesses，report `184145c:src/cvevidence/analysis_report.py:25-28` 只輸出 evidence_id/value/reason/witnesses，均沒有此 X-ID、行號與原文。

最小失敗測試：`tests/qa_contract/test_consumers.py:test_real_excerpt_locator_is_available_to_reviewer[renderer|report]`，實際 2 FAIL。修正方向是呈現核心既有 excerpts，連接同 run/context 來源工具；不能由 witness 自造行號或把保存內容標成當次重新核驗。

## 欄位對照與最小 mapping

| 核心欄位 | consumer 實測 | Runner／呈現建議 |
| --- | --- | --- |
| archive_sha256 | D 已核 catalog；consumer 不負責核驗 | 保留 blob digest 與原 archive |
| context_hash、input.context_hash | select_analysis 精確核對，PASS | envelope scope 與完整 payload 都保留，禁止跨 context |
| input.product_id/release_id/build_id/primary_artifact | B 真補件 compare_analyses PASS | declared_build_id 只對應 build_id；完整 input/artifact 仍要保留 |
| analyses[].cve_id | 3 個 CVE 各自選取；未知不當安全 | 舊單 CVE envelope 不足；保留完整 list，逐項狀態 |
| assessment.assessment_id | AI guard 使用，PASS | 保存不重算；同 context 仍須核對 A-ID |
| queries[] | 五 query_id/status/missing/conflicts/E-ID 接受 | 正式保存完整 query，不只 source list |
| evidence[].value/reason/witnesses | 真值、S-ID、path/hash 可呈現 | 分開工程 E-ID 與來源 S-ID |
| evidence[].excerpts[] | FAIL：兩 consumer 省略 | 保留 X-ID、source/file hash、行號、text/context，補導覽 |
| assessment.conditions[].state | SUPPORTED/UNKNOWN/BLOCKED 均顯示及匯出 | 不直接塞只接受 TRUE/FALSE 的舊型別；保留核心語意 |
| assessment.verdict | NEEDS_INVESTIGATION 及 B 補件 NOT_AFFECTED 接受 | 判定與執行狀態分開 |
| ai.context_hash/cve_id/engineering_assessment_id | OFFLINE 與 B 真 Live 失敗紀錄皆存在且相符 | **無缺身分轉接；不得補造或覆寫 ID 來通過 guard** |
| ai.mode/status/tasks/calls | OFFLINE、SIMULATED、LIVE/BUDGET_EXHAUSTED 可顯示；renderer 保留 response IDs | 細項狀態、calls 應完整保存，不以頂層 INCOMPLETE 取代 |
| later.analyses[].engineering_assessment_id | 延後 wrapper 外層及內層 ai 都有 A-ID | 核 context、唯一 CVE、兩層 A-ID 後掛回該工程 entry |
| investigation_verification | 核心獨立 linkage；本輪實際均 null | 原值保存；成功重判呈現 NOT_RUN，勿用別輪結果補填 |

`workflow.py:58-60` 的延後 AI wrapper 不含原 engineering assessment/queries/evidence，直接取代完整 payload 時，實測會失去工程判定並被 AI guard 拒絕。原因是階段結果不能替代完整工程結果，並非缺 ai.cve_id。

最小 QA 參考在 `scripts/qa_contract/later_ai_probe.py:checked_attachment`：深拷貝工程資料，核對 context/CVE/外層及內層 A-ID，再掛入對應 entry 的 ai／investigation_verification，保留原 assessment。此為 QA 記憶體投影，沒有正式 Runner／保存能力；授權、immutable run、parent lineage 必須由正式整合處理。

## 版本差異與 B 資料

來源工具有可重現的版本差異：`a47a1a3:src/cvevidence_core/sources.py:26` 將 context_hash 納入 X-ID digest，`44efc7b` 同一行將它排除。對相同 context/source/26–37 行/原文字元，舊 Runner 回 `X-89032895146813dd8274b829`，新核心為 `X-9d2a37a057d8b87a89828de6`，其他欄位完全一致。這是跨版本識別規則差異，不是 bytes 不符。主對話／Frankie 應讓正式分析及來源工具使用同一核心版本，不能只接新 payload 而保留舊 X-ID verifier。

B 已完成工程輸出複用自 `ai-validation-r2/var/validation/parallel-ai-r2/20260912T060516180542-r2-mock-b924ca36`。已核 summary 固定核心 SHA、engineering-readiness PASS，逐檔複製到 D run、記錄 SHA256，並確認讀取過程原檔未變。工程前後 JSON 都來自真 archive/補件，不是人工成功樣本；同目錄的 timeout/invalid-citation AI 保持 SIMULATED，API=0。

另外唯讀取得 B 已結束的 `20260912T060523891384-r2-live-3f42af5f`：NATIVE_LIVE、gpt-5.6-sol/medium、8 次 API、AI 73.196 秒，BUDGET_EXHAUSTED/INCOMPLETE，未成功重判。D 只驗 consumer 保留此失敗狀態與原工程 NOT_AFFECTED，不將它宣稱成功 Live，也不把 8 次 API 列為 D 的操作。

B 補件工程 context 為 `41348a539faeb6f88e9274fab8e216a60024e2e47096cde630fea45d69d6dcc3`，assessment 為 `A-75fd0fdec9e66e059816de1354ecc67ccde38c91295974ffc3fd3564307620de`。舊 AI 掛新 context、新 AI 掛父 context 均拒絕，工程保持原值。因 followup=null，成功 AI 新 evidence 與重判顯示留 NOT_RUN。

## 命令、計數與原始結果

命令 cwd 均為上述 D worktree。系統 Python 無 pydantic，因此只在自己的 ignored var 建 QA venv，實際安裝 pydantic 2.13.5／pytest 9.1.1，恰與指定 integration 的 requirements.txt 相符；freeze 在 `var/validation/parallel-contract/qa-venv-dependencies.txt`。不需安裝 Streamlit，因為本輪只用 recording fake。

```bash
python3 -m venv var/validation/parallel-contract/qa-venv
var/validation/parallel-contract/qa-venv/bin/python -m pip install 'pydantic>=2.6,<3' pytest
python3 scripts/qa_contract/probe.py
var/validation/parallel-contract/qa-venv/bin/python scripts/qa_contract/integration_probe.py --engineering var/validation/parallel-contract/run-20260912T060439734452Z/engineering.json
var/validation/parallel-contract/qa-venv/bin/python scripts/qa_contract/acceptance.py --engineering var/validation/parallel-contract/run-20260912T060439734452Z/engineering.json --b-run /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/ai-validation-r2/var/validation/parallel-ai-r2/20260912T060516180542-r2-mock-b924ca36
python3 scripts/qa_contract/later_ai_probe.py --b-run /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/ai-validation-r2/var/validation/parallel-ai-r2/20260912T060516180542-r2-mock-b924ca36 --b-run /home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/ai-validation-r2/var/validation/parallel-ai-r2/20260912T060523891384-r2-live-3f42af5f
git diff --check
git diff 44efc7bdcc533760ab167a2a005b0111b9758483 -- src contracts demo-inputs
```

acceptance.py 真正呼叫 `python -m pytest -q -p no:cacheprovider tests/qa_contract --junitxml=<本次run>/junit.xml`；只讀已複製結果，不重跑核心或 API。

結果皆在 `/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/contract-qa/var/validation/parallel-contract/`：

| run | 真正工作／結果 | 耗時 |
| --- | --- | --- |
| run-20260912T060439734452Z | 1 真 archive、3 CVE consumer 選取；基本相容 PASS | 2.334 秒 |
| integration-20260912T060658296068Z | 1 真 Runner 收件/保存/來源、analyze 拒絕、6 類映射拒絕；全分析接線 FAIL | 3.451 秒 |
| acceptance-20260912T060842877733Z | 16 pytest：14 PASS、2 FAIL、0 skipped/errors；兩 FAIL 為 locator | pytest 0.296 秒；含複製/啟動 1.850 秒 |
| later-ai-20260912T060953813116Z | 3 份 B 完成紀錄、30/30 介面檢查 PASS；不是 30 pytest | 0.248 秒 |

初始 run 保存 engineering/events JSON、逐 CVE renderer recording/報告、版本 provenance。Integration run 保存 Git snapshot、真 store、runner-return、來源 excerpt、mapping errors、stdout/stderr。Acceptance run 保存 JUnit、pytest stdout/stderr、B 來源 digest。Later-AI run 保存原 B JSON、明確標 QA_ONLY 的投影、renderer recording、報告與 provenance。原始結果均 ignored，未提交。

兩個 locator 測試保留為失敗回歸例，沒有改為 xfail 或假 PASS。未重跑 75 項、9 格、CMake Live、C 的補件規則/錯誤邊界；沒有呼叫 API、操作瀏覽器/正式服務。未驗項目按上表保持 NOT_RUN。

目前工具沒有跨對話傳訊能力；未宣稱已通知主對話 `01a09347-f3e1-77a3-b66f-f1f2877bef7a`，請主對話讀 `docs/sync/Parallel_Contract.md` 與本分支 commits。依 D01/D02/D03/D05/D06/D07/D08/D09 保留版本、分工、真測試、限制；AI scope 只驗資料身分及顯示，不宣稱已完成語意引用驗證。
