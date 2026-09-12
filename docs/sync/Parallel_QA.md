# Parallel QA 第二輪同步

更新：2026-09-12T14:08:42+08:00。**DONE：PASS 16／FAIL 0；135.215 秒；核心通過／網頁未驗。沒有新產品 blocker。**

## 主對話可直接接收

- 固定基準 `44efc7bdcc533760ab167a2a005b0111b9758483`；分支 `codex/parallel-qa-r2`；worktree `/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/qa-r2`。
- 第一輪 9/9、3/3、9/9 已在此基準整合，不算本輪新完成數；下方歷史所寫「未合入」是當時狀態。
- 本輪程式／首筆交件 `6f83e9d5998751e67d338a3cb1534666363ce68b`；最後摘要另隨文件 commit 交付。未合入主線、未 push／部署；主對話統一整合。
- 本輪只新增 `scripts/qa_parallel/merged_rom_probe.py` 與更新自己的兩份 MD，產品 src／contracts／原測試／UI／Runner／原驗收程式均無 diff。
- 真正命令：`PYTHONDONTWRITEBYTECODE=1 python3 scripts/qa_parallel/merged_rom_probe.py`，執行一次、exit 0。16 項包含五個工程分析、三個 OFFLINE 重核、六個拒絕情境、兩個身分／最終檢查。
- 實測：原 ROM 03＋中性／歷史停用聲明 NEEDS_INVESTIGATION（1.793 秒）→ 同 build 補件3862檔 → NOT_AFFECTED（adapter 13.088秒）；原 M-ID／source_context 保留，pending review 1→0，成品 bytes/hash 不變、新 context。
- 中性文字維持 NOT_AFFECTED；歷史相反聲明與未覆蓋入口皆維持 NEEDS_INVESTIGATION，正式 conditions 不被文字改寫。主線重核 helper 不另傳 statements 時亦保留歷史、pending 與結果。
- 錯 build delta、delta inventory/hash、衝突覆寫、archive hash、stale context、錯配 saved engineering 皆拒絕；每個失敗後核對原 archives、snapshots、記憶體結果及已保存 JSON 未污染。

## 第一筆 JSON 與完整報告

輸出根目錄：`var/validation/parallel-qa/merged-rom-r2-20260912T060449958481Z/`（本 worktree）。

- `01-original-with-statements.result.json`：第一筆真實工程結果，139204 bytes，NEEDS_INVESTIGATION。
- `02-supplemented-history.result.json`：補件後真實結果，1210728 bytes，NOT_AFFECTED。
- 上述同名 `.events.json`、`supplement-plan.json`、`04`–`09` 分析／重核 JSON，以及 `report.json` 均可直接讀取。
- 補件前 context `362de586a0b4155ecfb281efd23d1571cfc6e4156833f910dc1ada01fa0d1726`；補件後 `ed299a3ed9594dcbaf3fdb8a67a0e0461c8be8a510fdc1750b307058c3ce96a3`。QA package ID 與正式 Runner 可不同。
- report 記錄實測 HEAD `44efc7b`、核心逐檔 SHA-256、命令、依賴、腳本 SHA。執行時形成的程式 commit 不誤寫為先前測試 HEAD。實測後腳本內容 hash 未改。
- 依賴 Python 3.12.3／readelf 2.42／unsquashfs 4.6.1；無新安裝或重建。語法與 git diff --check 通過。
- 詳細實測表、line references、time caveat 與限制：`docs/releases/Parallel_QA.md`。16 最終檢查未獨立計時，原 report 0 為佔位；總135.215秒完整計時。

## NOT_RUN／範圍限制

Live API、正式 UI／Runner 保存／parent run／報告、75項單元、CMake Live、原九格全套、效能壓測，以及基準後的新核心 commit 均未驗。07–09 是使用真實 OFFLINE record 的直接核心重核，沒有 AI 新證據，不冒稱 Live成功；15 在 context gate 即拒絕，未進入 Live 或讀設定。

本輪沒有產品修正需求；測試完成即交件，不等待或輪詢新版本。若主線提供新 checkpoint，只依差異補驗。跨對話 callable 仍不可用，這份 MD 與 commit 供主對話主動讀取，未宣稱已發送訊息。

---

# 第一輪歷史同步

更新：2026-09-12 13:49（Asia/Taipei）。僅 C 對話維護。**核心通過／網頁未驗。**

## 給主對話與 Frankie 的交接

- 基準：`b89059fdd1f751b43559187fd488844c9eeb3336`；分支 `codex/parallel-qa`。
- Worktree：`/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/qa`。
- 第一筆交件：`63520e182c1aadec897b50a93bdb23bfaefec343`；完整 QA 程式交件：`b431c8a892fed7d348ed2bf9b6ccb12b35d6ce21`。本摘要另隨後續文件 commit 交付。全部尚未合入主線。
- 真實 Git archive → `analyze_archive_for_runner` 九格 9/9、三條同 build 補件 3/3、錯誤／狀態邊界 9/9。舊工程驗收、31 項單元與 30 次穩定性不計入本輪，也未重跑；六個產品未重建。
- ROM 03 第一筆：`NEEDS_INVESTIGATION`，AI `OFFLINE`，2.683 秒，432 sources / 8 evidence / 9 events；JSON/context/hash 與暫存清除通過。
- ROM 03 補件後 `NOT_AFFECTED`，CMake 06／curl 09 補件後 `AFFECTED`；三者同 build、成品 bytes/hash 不變、新 context／assessment，原 snapshot／Git archive 不變。
- 第一筆命令：`PYTHONDONTWRITEBYTECODE=1 python3 scripts/qa_parallel/adapter_probe.py`。最小 ROM 補件：`PYTHONDONTWRITEBYTECODE=1 python3 scripts/qa_parallel/supplement_probe.py --initial-report var/validation/parallel-qa/archive-20260912T054111493886Z/report.json`。其他 worktree 請代入自己的新報告路徑。
- 依賴：Python 3.12.3、GNU readelf 2.42、unsquashfs 4.6.1；無新安裝。每個 report 記錄測試 HEAD 與全部核心檔 SHA-256。

## 需要主線／Frankie 接手的最小需求

1. 損壞 archive 直接拋出 `tarfile.ReadError`，不是 `IntegrityError`／`UnsupportedError`。請主線 adapter 負責者確認統一例外，或 Frankie 的外層納入 tar/ZIP 解包錯誤。
2. 收件前失敗没有 stage event，也沒有結果 dict；Runner 需用例外路徑保存失敗與 assessment=null，不能只靠事件清除進度。C 未改 Runner 或產品程式。
3. 未知 CVE 的外層狀態為 `COMPLETED`，analysis 為 `UNSUPPORTED_CVE`，工程/AI `NOT_RUN`、assessment/ai=null；UI 不能只看外層成功。
4. 正式 UI、保存／parent run、Live、報告下載及 A/B／主線新 commit 均未驗。截至交件未收到新 commit；收到後只補驗受影響項。

## 檔案與證據

改動只有三個 `scripts/qa_parallel/` 腳本及自己的兩份 MD；沒有修改 `src`、contracts、原測試或原驗收報告。詳細實測值、精確命令、耗時與限制見 `docs/releases/Parallel_QA.md`。

原始資料只存本 worktree 的 `var/validation/parallel-qa/`：

- `archive-20260912T054111493886Z/`：ROM 03。
- `archive-20260912T054300647924Z/`：其餘八包。
- `supplements-20260912T054433782100Z/`：三條補件。
- `boundaries-20260912T054544993791Z/`：九項錯誤／狀態邊界。

每個目錄有 `report.json`，實際分析另存完整 JSON 與 events；補件計畫亦保留。四個實测命令 exit 0；語法與 `git diff --check` 通過。程式未修改後不反覆重跑。

通知限制：本對話工具清單無 `send_message_to_thread`，無法直接投遞至主對話 `01a09347-f3e1-77a3-b66f-f1f2877bef7a`。此檔是可讀交接，未宣稱訊息已送達。未推送、未發布、未合入主線。
