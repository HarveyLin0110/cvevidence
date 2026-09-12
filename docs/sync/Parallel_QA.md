# Parallel QA 第二輪同步

更新：2026-09-12T14:03:23+08:00。**RUNNING：首筆工程＋補件 3/3 通過；其餘項目執行中。**

- 固定基準：`44efc7bdcc533760ab167a2a005b0111b9758483`；worktree `/home/cvevidence/work/CVEvidence_Fresh_2026-09-12/var/parallel/qa-r2`；分支 `codex/parallel-qa-r2`，已核對乾淨。
- 第一輪三支 QA 腳本與 9/9、3/3、9/9 摘要已隨 `0a480df`、`ab44f09`、`44efc7b` 整合；下方第一輪交件狀態為歷史紀錄，不作本輪結果。
- 本輪產品差異：A 的 statement_context／statement_reviews 分離與補件後重新比對；主線 workflow 保留歷史文字、OFFLINE／後續調查重核入口；B 的 AI 可靠性；buildproof 關閉檔案 handle。adapter 未變。
- 聚焦 ROM 03 真實 archive → 缺件 → 同 build delta → 阻斷，持續保留中性／歷史文字；真正衝突／未覆蓋入口仍待查；失敗補件／context／hash 不污染原 input／結果。
- 首筆 ROM 03 archive 1.793 秒 → NEEDS_INVESTIGATION；補件後 archive 13.088 秒 → NOT_AFFECTED，同 build／成品 bytes 不變，新增 3862 檔，新 context `ed299a3ed9594dcbaf3fdb8a67a0e0461c8be8a510fdc1750b307058c3ce96a3`。原 M-ID／來源 context 保留，原待查聲明改為 CONSISTENT_WITH_VERIFIED_EVIDENCE，pending reviews=0。
- 真正執行命令：`PYTHONDONTWRITEBYTECODE=1 python3 scripts/qa_parallel/merged_rom_probe.py`。當次輸出 `var/validation/parallel-qa/merged-rom-r2-20260912T060449958481Z/`，第一筆工程 `01-original-with-statements.result.json`、補件後 `02-supplemented-history.result.json`、各自 events、`supplement-plan.json`、漸進 `report.json` 可供主對話讀取。
- 75 項原測試、CMake Live 與第一輪全套不重跑。衝突／未覆蓋入口／重判／失敗不污染驗收仍在執行。
- NOT_RUN：Live API、正式 UI／Runner／報告、全量效能。沒有跨對話 callable；主對話請讀本檔／commit，未宣稱訊息已投遞。

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
