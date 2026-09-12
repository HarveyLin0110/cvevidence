# Parallel QA 第二輪：合併後 ROM 補件與歷史語意

更新：2026-09-12T14:08:42+08:00。**PASS 16／FAIL 0；總耗時 135.215 秒；核心／adapter 通過，網頁未驗。** 本輪無新產品 blocker。

## 固定基準與實際變更

- 基準：`44efc7bdcc533760ab167a2a005b0111b9758483`，已包含 A/B/C 第一輪整合與 workflow 修正。
- 分支：`codex/parallel-qa-r2`；新 worktree：`/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/qa-r2`。原第一輪 worktree 留存、未寫入。
- 第一輪 QA 程式與 9/9、3/3、9/9 摘要已整合為 `0a480df`、`ab44f09`、`44efc7b`，下方第一輪文件只作歷史，不列本輪完成數。
- 相對第一輪基準，產品改動為 assessment/supplements 的中性與歷史聲明分類、workflow/investigation_evidence 的歷史保留與重判、ai 的工具可靠性，以及 buildproof 關閉 ELF handle。archive adapter 未變。本輪集中跨 A 與主線 workflow 的 ROM 路徑。
- 新增腳本只有 `scripts/qa_parallel/merged_rom_probe.py`；另更新自己的 release/sync MD。`src`、contracts、原測試、UI、Runner、原驗收腳本均無 diff。
- 程式／首筆交件：`6f83e9d5998751e67d338a3cb1534666363ce68b`。這次實際執行 HEAD 為基準 `44efc7b`，執行期間提交自有 QA 檔；測試腳本 SHA-256 `9f022c262dfcb04dad4927075256cebf7bb09e47daf608a554f2ae868be69771`，實测前後相同。文件另隨後續 commit 交件，未合入主線／未推送。

## 可重現命令與第一筆 JSON

依賴 Python 3.12.3、GNU readelf 2.42、unsquashfs 4.6.1，直接匯入此 worktree 的 `src`，沒有安裝、建置、Live API 或環境檔讀取。所有解包串行，生成暫時的無壓縮 tar 送 adapter，沒有建立正式保存／Runner 系統。

在指定 worktree 根目錄實際執行一次，exit code 0：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/qa_parallel/merged_rom_probe.py
```

這是本輪 16 個針對性檢查項的命令；未重跑 75 項單元、第一輪九格／補件／邊界全套、CMake Live 或效能壓測。

原始 run 資料：`var/validation/parallel-qa/merged-rom-r2-20260912T060449958481Z/`。主對話可直接讀取：

| 檔案 | 真實內容 |
|---|---|
| `01-original-with-statements.result.json` | ROM 03 archive＋中性說明＋停用 heartbeat 聲明；NEEDS_INVESTIGATION，pending review=1，1.793 秒 |
| `02-supplemented-history.result.json` | 同 build delta 補回 3862 檔後 archive 分析；NOT_AFFECTED，pending review=0，13.088 秒 |
| 同名 `.events.json` | 兩次實際 INGEST→QUERIES→VERIFY→ASSESS→AI/OFFLINE，共各 9 events |
| `supplement-plan.json` | 真實 validate_supplement 新增檔案計畫 |
| `04-...` 至 `09-...result.json` | 中性／衝突／未覆蓋入口的真實分析與 OFFLINE 重核結果 |
| `report.json` | 固定與實測 commit、核心逐檔 SHA-256、QA 腳本 hash、依賴、各項 PASS/FAIL、耗時與錯誤 |

第一筆 JSON 139,204 bytes，SHA-256 `d648c98046c4196ed8494b80f9a09a6520002cb79448ab77583076a0a1d985ea`；補件後 JSON 1,210,728 bytes，SHA-256 `1ece64b8f0926fbea18b71dadc28142e7726862a0b6813b3d699687352c76fee`。這些是實際檔案，非預填／mock 結果。

| 身分 | 補件前 | 補件後 |
|---|---|---|
| Build | `rom-20260912T043812-0b9b1a` | 相同 |
| 成品 SHA-256 | `9ee6e6d88ca2796266798e62130b4c30d48bdb7101df3f4a9115966577582d92` | 相同，亦核對 bytes |
| Context | `362de586a0b4155ecfb281efd23d1571cfc6e4156833f910dc1ada01fa0d1726` | `ed299a3ed9594dcbaf3fdb8a67a0e0461c8be8a510fdc1750b307058c3ce96a3` |
| Assessment ID | `A-2f18a9f7a5029c11e1d1885b81268b828311d4723edafa47b89ba6541b929d55` | `A-20983bdec10388feb220c5ca0df5f3a96eecf4ec5c3ee0e7bbbb70e30c845aad` |

## 16 個檢查項的實測結果

全部 PASS，沒有 FAIL。以下為檢查項而非 16 次獨立全案分析：五次工程分析（兩次真實 archive、三次同 snapshot workflow）、三次 OFFLINE 重核、六種拒絕／隔離、兩項身分與最終完整性檢查。

| 項目 | 實際結果／條件 |
|---|---|
| 01 原始 archive＋聲明 | NEEDS_INVESTIGATION；口述未補足工程證據；歷史／中性原文與 M-ID 保留 |
| 02 同 build delta＋原歷史 | NOT_AFFECTED；原聲明重新核對為 CONSISTENT_WITH_VERIFIED_EVIDENCE |
| 03 身分／歷史轉換 | 同 build、相同成品 bytes、新 context；vulnerable_implementation=BLOCKED；原 M-ID／source_context 保留 |
| 04 新中性文字→workflow | NOT_AFFECTED；pending reviews=0，所有工程 conditions 不變 |
| 05 舊 context 的「heartbeat 已啟用」 | NEEDS_INVESTIGATION；CONFLICTS_WITH_VERIFIED_EVIDENCE，工程 conditions 不變 |
| 06 舊 context 的未交付網路入口 | NEEDS_INVESTIGATION；UNRESOLVED_SCOPE，工程 conditions 不變 |
| 07–09 主線重核 helper | 不另傳 statements，由原 statement_context 還原；歷史／衝突／未覆蓋入口各自維持原 verdict、pending reviews、conditions，原結果 dict 不變 |
| 10 錯 build delta | DIFFERENT_BUILD／can_merge=false |
| 11 補件 inventory/hash 錯誤 | IntegrityError: Supplement inventory or hash mismatch |
| 12 同 build 衝突覆寫 | IntegrityError: Conflicting replacement … build/build-record.json |
| 13 archive SHA 不符 | IntegrityError: 工程壓縮包 hash 不一致 |
| 14 新 snapshot 使用舊 context | IntegrityError: 分析快照與原 run 不一致 |
| 15 分段 workflow 錯配已存工程結果 | IntegrityError: AI 階段不屬於已保存的工程快照；在任何 LIVE 階段／設定讀取前拒絕 |
| 16 最終完整性 | 初始／補件 archives、base／merged snapshots、原前後記憶體 dict、保存 JSON 均未污染；有效 delta 恢復後仍 READY_FOR_NEW_SNAPSHOT |

每個拒絕情境均重新核對原 snapshots、記憶體结果 digest、原 archive 與保存 JSON 檔案 hash；不是只檢查 exception 名稱。負向補件只改自己的暫存 delta 副本，均 finally 還原；沒有覆寫原 Git demo 包。

總 wall time 135.215 秒為實測。03 的 17.653 秒包含建立補件快照與 02 的 adapter 分析，不能把各列耗時相加；16 未獨立計時，原始 report 的 0 是未計時佔位，不表示耗時為零，已含在總 wall time。保留原始 report 不回填修改。

## 接線語意與未驗範圍

- workflow 接受 persisted M-ID dict 時保留原 `source_context_hash`，每次由目前 snapshot 重評。相關已讀位置為 `src/cvevidence_core/workflow.py:26`、`assessment.py:59`，以及重核恢復歷史的 `investigation_evidence.py:40`。
- 「歷史」在本輪指前一次 snapshot 保存的 M-ID／原文及來源 context；不宣稱能理解所有任意歷史敘述。測试中性字句與具體衝突／範圍句型，沒有放寬判定規則。
- 07–09 將真實 OFFLINE 分析紀錄交給 `reassess_after_investigation`，測它重新驗證／還原聲明的純核心邊界。沒有偽造 Live 紀錄或 AI 新證據，new_evidence=[]；這不是 Live 完整串接成功。
- 15 只驗 `workflow.py:45` 的 context 拒絕分支。LIVE 成功路徑、工具呼叫與 workflow.py:57 自動後續重判均 NOT_RUN；本輪沒有呼叫 Live API。
- `supplements.py:14` 的不同 build 是拒絕合併的回傳狀態；`supplements.py:12/20` 與 adapter hash/context 錯誤是例外。實際 Runner 保存失敗／畫面狀態仍 NOT_RUN。
- 正式 UI／Runner／parent run／報告下載、B/D 其他驗收、75 項原測試、CMake Live、全量效能及任何後續核心 commit 均未驗。QA 用自己的 package ID，context 不必等於正式 Runner 的快照。
- 未發現本輪範圍內需要修正的產品問題。沒有更動產品 src／contracts／UI／Runner／原報告，沒有 merge、push、部署；收到新 checkpoint 才按差異追加，不空轉等待。
- 本對話沒有可用的跨對話發訊工具。結果／首筆小 commit 已寫自己的同步 MD，供主對話主動讀取，未宣稱訊息送達。

---

# 第一輪歷史：固定 checkpoint 接線驗收

**核心通過／網頁未驗。** 新增 archive 接線驗收九格 9/9、補件 3/3、錯誤／狀態邊界 9/9。本輪只驗 Git `demo-inputs/` → 核心 adapter 的真實邊界；不把資料交付、mock、既有驗收或舊 `var` 成品計作新的端到端成功。

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

尚未驗 Frankie 正式網頁、Runner 保存/parent run、Live 金鑰程序、畫面錯誤狀態與報告下載；不能由 adapter 成功推論端到端通過。本輪已補齊以下 archive／補件邊界；截至交件未收到 A/B 新 commit，A/B 與正式整合版本未驗，之後只驗受影響項。


## 本輪完整實測：串行 archive 邊界

初始包各分析一次，輸入全來自今日 Git `demo-inputs/`；沒有重跑原工程驗收、單元測試或穩定性全套。下表的秒數是實際 adapter 呼叫耗時，受本機負載影響，不是網頁延遲保證。

| 初始包 | 實測 verdict | Adapter 秒數 | 結果 |
|---|---|---:|---|
| ROM 01 | AFFECTED | 13.616 | 通過 |
| ROM 02 | NOT_AFFECTED | 16.456 | 通過 |
| ROM 03 | NEEDS_INVESTIGATION | 2.683 | 通過 |
| CMake 04 | AFFECTED | 0.963 | 通過 |
| CMake 05 | NOT_AFFECTED | 0.560 | 通過 |
| CMake 06 | NEEDS_INVESTIGATION | 0.380 | 通過 |
| curl 07 | AFFECTED | 11.258 | 通過 |
| curl 08 | NOT_AFFECTED | 19.441 | 通過 |
| curl 09 | NEEDS_INVESTIGATION | 11.539 | 通過 |

九次 adapter 秒數合計 76.896；每包都有 5 queries、8 evidence、9 events，以及全部 11 項邊界檢查。這不是原工程報告的 80.060 秒。

| 補件基底 | 補件前 → 後 | 新增檔案 | 補件後 adapter 秒数 | 包含解包／驗補件／組快照總秒數 |
|---|---|---:|---:|---:|
| ROM 03 | NEEDS_INVESTIGATION → NOT_AFFECTED | 3862 | 10.894 | 17.859 |
| CMake 06 | NEEDS_INVESTIGATION → AFFECTED | 149 | 1.312 | 2.254 |
| curl 09 | NEEDS_INVESTIGATION → AFFECTED | 5 | 14.673 | 28.361 |

沿用 `validate_supplement` → 複製到拋棄式 QA snapshot → 僅加入 `added_files` → `scan` 生成新 manifest → re-ingest → archive adapter。為減少 CPU 負載，暫時用不壓縮的 tar 送 adapter；未另建正式 Runner／保存系統。原始結果沿用本輪先前實測，不再次分析基底；程式先核對核心 SHA-256、catalog、archive/context 與預期 verdict，才接受先前報告。

三條皆核對同 build、成品檔案 bytes/hash 相同、原 snapshot 與 Git archives 不變、新 assessment/context、獨立 re-ingest 的 context 被 `expected_context_hash` 接受。快照與暫時 tar 離開測試即清除，結果／events／補件計畫保留。

| 基底 | 補件後 context hash |
|---|---|
| ROM 03 | `a6fab5c228c1f805ce4a2c0ab74bbf2ef9e9b08c35e35e70c64f0a68c6e4a460` |
| CMake 06 | `140bb352ba077171aa9781784c5e9b68ec64d0e8212327da9b78b22e6fa2e2b4` |
| curl 09 | `dfa8a0388599b46955f9d03e72b7cf94b935549d09a5a339e5321bded33eb941` |

QA snapshot 使用自己的 package ID，因此補件後 context 不必等於正式 Runner 未來建立的 snapshot；這不是跨 run 身分保證。

## 錯誤與狀態實測，以及 Frankie 最小接線注意事項

`boundary_probe.py` 九項均符合基準的實際邊界行為；沒有調用 API 或注入 mock transport：

| 測項 | 真實回傳／例外 |
|---|---|
| 不存在、空檔、symlink archive | `IntegrityError`：無效的工程壓縮包 |
| 錯誤 archive SHA-256 | `IntegrityError`：工程壓縮包 hash 不一致 |
| 錯誤 expected context | `IntegrityError`：分析快照與原 run 不一致 |
| 不支援的 options key | `ValueError`：不支援的分析選項 |
| 真實損壞的 archive bytes | `tarfile.ReadError`；沒有結果物件 |
| 未知 CVE（真實 ROM archive） | 外層 `COMPLETED`，該分析 `UNSUPPORTED_CVE`，assessment/ai 為 null，工程/AI 皆 `NOT_RUN` |
| 無檔案現象（workflow 入口） | `AWAITING_INPUT`、空 analyses、工程/AI 皆 `NOT_RUN` |

前七個拒絕情境皆無結果、無 stage event，暫存清除通過。這證明核心未回傳成功 assessment，**不代表正式 Runner 已保存失敗狀態**。最小接線需求：

1. Runner 的呼叫外層必須處理例外並保存失敗與 assessment=null；不能只依 event_callback 結束進度。完整性檢查與解包發生在首個 INGEST event 之前。
2. 損壞 archive 的 `tarfile.ReadError` 尚未統一為核心 `IntegrityError`／`UnsupportedError`。請主線 adapter 負責者確認是否統一例外，或 Frankie 明確涵蓋 tar/ZIP 解包例外；C 未改產品程式。現有測試記錄這個相容性缺口，未宣稱已修正。
3. UI 必須讀每個 analysis 的狀態與工程/AI 狀態；外層 `COMPLETED` 只表示呼叫完成，未知 CVE 沒有 assessment。
4. 正常 OFFLINE 事件末端是 `AI/OFFLINE`；ASSESS 只有 COMPLETED。Live、等待補件、API_ERROR／TIMED_OUT 的正式畫面仍待 Frankie 實測。

## 實際操作命令與原始報告

在指定 QA worktree 根目錄，依序執行過，四個命令退出碼均為 0：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/qa_parallel/adapter_probe.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/qa_parallel/adapter_probe.py --cases 01_rom 02_rom 04_cmake 05_cmake 06_cmake 07_curl 08_curl 09_curl
PYTHONDONTWRITEBYTECODE=1 python3 scripts/qa_parallel/supplement_probe.py --cases 03_rom 06_cmake 09_curl --initial-report var/validation/parallel-qa/archive-20260912T054111493886Z/report.json --initial-report var/validation/parallel-qa/archive-20260912T054300647924Z/report.json
PYTHONDONTWRITEBYTECODE=1 python3 scripts/qa_parallel/boundary_probe.py
```

新 clone 可先只執行第一個命令，再把新產生的 `report.json` 路徑交給 `supplement_probe.py --initial-report ...`；預設補 ROM 03。不傳先前報告也可獨立執行補件腳本，會先真實分析基底。`--cases` 只選需要補驗的案例，不要求全套重跑。

原始報告皆在 QA worktree 的 `var/validation/parallel-qa/`：

- `archive-20260912T054111493886Z/report.json`：首筆 ROM 03，測試 commit 為基準 `b89059f`。
- `archive-20260912T054300647924Z/report.json`：其餘八包，測試 commit `63520e1`。
- `supplements-20260912T054433782100Z/report.json`：三條補件，測試 commit `63520e1`。
- `boundaries-20260912T054544993791Z/report.json`：九項錯誤／狀態邊界，測試 commit `63520e1`。

原始 report 中逐檔核心 SHA-256 一致；`63520e1` 只增 QA 腳本與自己的文件，產品核心仍等於基準。補件／邊界脚本當時為未提交的自有檔，實測後以相同內容提交為 `b431c8a892fed7d348ed2bf9b6ccb12b35d6ce21`，不將該 commit 誤寫為先前實測 HEAD。語法檢查與 `git diff --check` 通過；相對基準的 `src`、原測試、contracts、原驗收腳本皆無 diff。

## 交件與限制

- 第一筆重現交件：`63520e182c1aadec897b50a93bdb23bfaefec343`。
- 完整 QA 程式交件：`b431c8a892fed7d348ed2bf9b6ccb12b35d6ce21`；本文件另以後續文件 commit 交付，精確文件 commit 可用 `git log -1 -- docs/releases/Parallel_QA.md` 查得。
- 改動範圍只有 `scripts/qa_parallel/{adapter_probe,supplement_probe,boundary_probe}.py`、`docs/releases/Parallel_QA.md`、`docs/sync/Parallel_QA.md`。
- 未驗正式網頁、Runner 保存／parent run／下載、Live AI、A/B 後續改動及主線整合；未發布、未推送、未合入主線。
- 本對話未提供 `send_message_to_thread` callable，無法直接投遞主對話。交接摘要已存自己的同步檔，不能宣稱已通知送達。
