# Parallel QA：固定 checkpoint 接線驗收

**核心通過／網頁未驗。** 本輪只驗 Git `demo-inputs/` → 核心 adapter 的真實邊界；不把資料交付、mock、既有驗收或舊 `var` 成品計作新的端到端成功。

## 基準與操作

- 測試基準：`b89059fdd1f751b43559187fd488844c9eeb3336`（完整核心 `cb257c3` 加分工交接）。
- 分支：`codex/parallel-qa`，worktree：`/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/qa`。
- 依賴：Python 3.12.3、GNU readelf 2.42、unsquashfs 4.6.1；核心 pyproject 要求 Python >=3.10，無第三方 Python 依賴。本輪直接匯入此 worktree 的 `src`，未安裝套件、未建置產品。
- 在含本交件的 repo 根目錄執行：`PYTHONDONTWRITEBYTECODE=1 python3 scripts/qa_parallel/adapter_probe.py`。
- 預設只跑 ROM 03；`--cases` 可明確選其他 Git 初始包。結果、事件、報告與暫存均在自己的 `var/validation/parallel-qa/`，每次建立新目錄；無 Live API 呼叫、無環境檔讀取。

## 第一筆實測

2026-09-12 05:41 UTC，實際 `demo-inputs/rom/03_rom.tar.gz`：

| 項目 | 實測值 |
|---|---|
| Verdict / 工程狀態 | `NEEDS_INVESTIGATION` / `COMPLETED` |
| AI 狀態 | `OFFLINE` |
| Adapter 耗時 | 2.683 秒（不含腳本的 catalog 預檢） |
| 來源 / 證據 / query | 432 / 8 / 5 |
| Stage events | 9；INGEST → QUERIES → VERIFY → ASSESS → AI |
| SHA-256 | `51a6edc8beb71530761eb486fba6f4c5cda029f65d12ed36c8a5a81dcf2bd7e0` |
| Context hash | `362de586a0b4155ecfb281efd23d1571cfc6e4156833f910dc1ada01fa0d1726` |
| Assessment ID | `A-45893395c61e816f7acb17afbeae75ad552e2a3652a3663de8e62dc781ff2d33` |

11 個檢查均通過：可嚴格 JSON round-trip、完成狀態、工程/AI 狀態分離、預期 verdict、五個 queries、四處 context 一致、archive hash、build/release/成品身分、實際事件序列與暫存清除。ASSESS 只有 COMPLETED，沒有 STARTED；這是基準的實際介面。

原始資料在 QA worktree 的 `var/validation/parallel-qa/archive-20260912T054111493886Z/`：`report.json` 保存測試 commit、每個核心檔 SHA-256、命令與依賴位置，另存完整結果及事件。原始執行結果不進 Git。

## 既有證據與未驗範圍

既有工程報告 `驗收證據/engineering-20260912T052948.json` 記錄九格 9/9、補件 3/3、五個反例，80.060 秒；穩定性報告記錄三個主展示輸入共 30 次 OFFLINE。兩者讀取已解包 `var/artifacts`，本輪不重跑、不列入本輪完成數。既有同步只記錄 CMake archive 成功；本次補第一筆 ROM archive 可重現結果。

尚未驗 Frankie 正式網頁、Runner 保存/parent run、Live 金鑰程序、畫面錯誤狀態與報告下載；不能由 adapter 成功推論端到端通過。後續只补尚缺 archive／補件邊界，A/B 新 commit 到達後只驗受影響項。
