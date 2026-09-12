# 平行任務 A：判定與文字補充語意

- 基準：`b89059fdd1f751b43559187fd488844c9eeb3336`。
- 分支：`codex/parallel-semantics`。
- 唯一工作區：`/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/semantics`。
- 修改範圍：`src/cvevidence_core/assessment.py`、`src/cvevidence_core/supplements.py`、`tests/test_statement_semantics.py`、本檔。
- 不修改主 checkout、workflow、AI、Verifier、Query、Runner、UI 或 contracts；不重建 demo，不啟動服務、不讀取金鑰。

## 第一個實測結果

14 項新增回歸測試通過。使用 worktree 的今日原始 demo archives 解包，經真正的 collect → verify → assess，未 mock 工程證據或執行上傳程式。

- 05_cmake 加入「已提供這次使用的檔案，請查核。」仍為 `NOT_AFFECTED`，原文、material ID 與來源 context 保留。
- 中性英文操作說明不改變 `AFFECTED` 或原有缺件判定。
- 口述停用不能補足缺件；與已驗條件相反的文字保留 condition ID 與可核對 evidence ID。
- 中性說明後接新增入口、否定、未知語意或要求直接判安全，不會被中性片段掩蓋。
- 同 build ROM 03 補件：保留原 context 的停用文字，從待查收斂為 `NOT_AFFECTED`。
- 同 build CMake 06 補件：保留原入口條件／具名成品文字，從待查收斂為 `AFFECTED`。
- 已存在的 source 檔案不等於已涵蓋的交付成品；具名成品需同時進入已驗 scope 與 product binding。
- 補件／context 改變不會自動解除真正矛盾或未涵蓋入口。
- 呼叫方塞入 resolved、blocks_verdict=false 或 verified_engineering_fact=true 等欄位不受信任；一律由原文重算。
- 現有 workflow 及 ai.py 的判定完整性閘門接受修正後的中性文字結果。

## 相容性與新增可選欄位（請主線知悉）

函式簽章與原有 Assessment 欄位不變。`statement_reviews` 僅保留會阻擋判定的具體未決事項，因此既有 ai.py 的非空檢查仍相容。新增可選 `statement_context`，僅在有文字時存在，保留所有文字（包括操作背景、已核對一致、未決）。無文字時不新增此欄位。

每筆保留 `statement_id`、`text`、`source_context_hash`、當次 `assessed_context_hash`、`reason`、`verified_engineering_fact=false`、`review_required=true`、`blocks_verdict` 與 `checks`。checks 包含完整片段、分類、核對狀態及 evidence IDs；能解析的工程主張另附 `condition_id`、`claimed_value`，具名交付成品另附 `path`。

`review_required=true` 表示仍須工程師覆核；`blocks_verdict` 才表示此次正式判定有未決事項。原文字永不成為條件證據。正式 `conditions`、`conflicts`、`evidence_ids` 均取自既有 Verifier，不由文字改寫。不讀取包名或預期答案、不使用模型分類。

## 規則的實際界線

採完整子句的有限確定性文法：常見中文／英文操作說明、明確 `condition_id=true/false`（亦支援 SUPPORTED/BLOCKED）、少數可精確對應 profile 的工程主張與具名交付成品。未知、否定、混合限定或無法完整解析的子句保守留待覆核；不是通用自然語言理解器。

新增且未經 profile 審查的入口不因提供任意檔案或換 context 就自動解除。若要分析新的入口語意，需要主線 Query/profile 負責者擴充可驗工程規則；本分支不擴張其所有權。

## 驗證與交付狀態

目前完成：

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -p test_statement_semantics.py -v
```

結果：14 tests，OK（12.628 秒）。

完整核心回歸：

```sh
mkdir -p var/semantics-tests
TMPDIR="$PWD/var/semantics-tests" PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
git diff --check
```

結果：45 tests，OK（23.976 秒），包含原有 31 項與新增 14 項；diff whitespace 檢查通過。未執行 Live API，不宣稱 Live 已驗。

所有修改及測試均在上述獨立 worktree；測試快照與暫存目錄在其忽略的 `var/semantics-tests/`。實作與本同步紀錄即將一起提交到獨立分支；提交後另補一個純文件 commit 記錄實作 commit ID，兩者都不代表主線已整合。

觀察到既有 `buildproof.py:39` 的檔案未關閉 ResourceWarning，非本任務修改範圍，不影響測試通過；已如實保留供主線處理。原有重複 ZIP 防護測試另產生預期的 Duplicate name UserWarning。

本對話可用工具沒有 `send_message_to_thread`，已在對話明示；尚無法直接發送通知到主對話。此同步檔先保存第一個結果，交件不代表已合入主線。
