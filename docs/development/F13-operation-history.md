# F13 手動來源操作紀錄
日期：2026-09-12。基於 F12 39f922f 的獨立功能分支 codex/frankie-operation-history；不修改整合端核心檔案。

## 實作
Runner.source_tool 的既有入口新增事件包裝，核心呼叫仍為 CoreService.tool。
每次先原子建立 START 收據，完成後另建 END。未能保存 START 時不呼叫工具；未能保存 END 時不回傳成功結果。
收據保存在 var/runtime/events/<run_id>/<event_id>.start.json／.end.json，run保存檔不變、已存事件不覆寫。
START含run/context、operation、timestamp、參數SHA256；END含SUCCESS/FAILED、結果SHA256或錯誤分類。
不保存搜尋詞、原文內容、任意例外文字、API key；摘要hash不是加密或資料來源認證，不宣稱完全防止猜測。
讀回核對event UUID、run、context與terminal狀態。缺少END呈現NO_TERMINAL_RECEIPT，不推測是成功或失敗。損壞／scope不符收據可見地排除、原檔保留。
這是本機手動list/search/excerpt/compare的追蹤，不是模型工具trace，也不涵蓋legacy reports.excerpt或呼叫者直接繞过Runner使用核心工具。

## 使用
- Runner.tool_history(run_id) 回傳 events 與 invalid_receipts。
- CLI：PYTHONPATH=src python -m cvevidence.cli --store var/runtime events RUN_UUID。
- Web報告頁新增「來源操作紀錄」展開區及JSON下載。
- 當前actor固定MANUAL_TOOL_CALL；Horace AI內部工具事件另依其正式介面對齊，不能混為手動操作。

## 驗收
68 pytest passed。新測試5項：成功／失敗與scope、沒有END、不覆寫terminal、竄改context拒讀、磁碟錯誤時阻止工具呼叫。
既有AppTest包含原文→報告與補件流程；這些測試通過，不代表語意引用或AI完整性已驗收。

## 整合
只改runner.py/cli.py/workspace.py，新增events.py。此功能分支以39f922f為基線，避免改動正在驗收的PR#4。
新核心分析整合時，請保持source_tool回傳結果格式；事件摘要只作追蹤，不用於判定。服務明確--port8505，Frankie本機仍8506。
