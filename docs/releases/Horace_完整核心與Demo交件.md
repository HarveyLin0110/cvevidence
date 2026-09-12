# Horace 完整核心與 Demo 交件

本次交付包含今日新建的資料、Q1–Q5、Verifier、三個 CVE 的工程規則、AI 動態調查、补件驗證／重新判定、中文摘要與獨立 CLI。正式網頁／Runner 保存與畫面整合仍由 Frankie 接續。

## 隊友先拿什麼

1. `demo-inputs/`：九個初始包與三個補件，12 個 tar.gz 共 95,147,059 bytes；已在 Git，不用從本機另外索取。中文選檔表見 [Demo 輸入說明](../../demo-inputs/README.md)。
2. [核心分析介面與接線提案](../architecture/核心分析介面與接線提案.md)：Frankie 可呼叫 `analyze_archive_for_runner` 或解包後的 `analyze_package(context, ...)`。
3. [三個 CVE 規則](../engineering/三個CVE規則與適用範圍.md)：判定條件、官方來源、scope 與限制。
4. [驗收證據目錄](驗收證據/)：機器可讀的實測結果與真實 AI 工具紀錄；失敗也保留。

輸入包交件 commit `8882c75`；完整核心及本文件在同一 `codex/horace-fresh-core` 分支、Draft PR #2。请更新到該分支最新 commit，避免只合入較早收件版。

## 今日實測結果

| 工程包 | 初始結果 | 補件後結果 |
|---|---|---|
| ROM 01 | Affected | — |
| ROM 02 | Not Affected：同 build 排除 heartbeat | — |
| ROM 03 | Needs Investigation | Not Affected；成品 hash 不變、新 context |
| CMake 04 | Affected | — |
| CMake 05 | Not Affected：修正後實作已綁定成品 | — |
| CMake 06 | Needs Investigation | Affected；成品 hash 不變、新 context |
| curl 07 | Affected | — |
| curl 08 | Not Affected：同版號官方修補已綁定成品 | — |
| curl 09 | Needs Investigation | Affected；成品 hash 不變、新 context |

九格 9/9、補件重判 3/3，獨立驗收端比對預期，核心不讀取答案。最後一輪工程驗收共 80.060 秒，包含補件、重新取證與五項反例，不是單次前端延遲。[完整工程紀錄](驗收證據/engineering-20260912T052948.json)

三個主展示輸入 ROM 03、CMake 04、curl 09 各 OFFLINE 重跑 10 次，共 30 次；結果、Assessment ID、Evidence ID 均穩定，沒有呼叫 API。這不是九包各重跑十次。[穩定性紀錄](驗收證據/stability-20260912T053053.json)

測試另涵蓋：篡改原值／ID／原文、改包名與顯示時間、口述不能改判安全、不同 build／覆寫補件、來源路徑逃逸、未知 CVE、API 逾時／429、越權工具、假引用、假 hash、假 assessment。修改已修正 source、增加另一個未涵蓋 binary、混入不同 build 紀錄，都轉為 Needs Investigation。[真包反例](驗收證據/adversarial-real-packages.json)

## 真實 AI：GPT-5.6 Sol／medium

模型為使用者選定，`OPENAI_MODEL=gpt-5.6-sol`、`OPENAI_REASONING_EFFORT=medium`，實際 Responses API 呼叫成功。金鑰由環境或忽略的 `.env.local` 提供。

| 當次情境 | 模型真正採取的行動 | 結果／AI 時間 |
|---|---|---|
| ROM 03：同事口述關閉 heartbeat | LIST／SEARCH／READ 核對現有 build/link 資料，再要求同 build 編譯與預處理材料 | 等使用者補件；53.463 秒 |
| CMake 04：更新匯入顯示 EOF | 讀正常與截短測試紀錄，比對 returncode、extra 長度與錯誤文字 | 完成；30.922 秒；未把 EOF 當成 CVE 根因 |
| curl 09：不知道現場 DNS 設定 | 先找 launcher/config，再列出執行設定與觀測缺口 | 等使用者補件；27.704 秒 |
| curl 07：材料一開始就提供 | 讀 config、launcher、SOCKS5 觀測與正常下載紀錄 | 完成；54.975 秒；沒有再要求補同一組材料 |

以上四筆已閱讀問題、工具輸出與最終摘要，內容符合對應 demo 資料，已接受的引用可核對。這是四個情境的實測，不是一般化正確率或速度保證；自由文字語意仍標為待工程師覆核。

保留一筆 curl 缺件調查的 `INVALID_CITATION`：模型生成了一個不存在的 X-ID，Verifier 拒絕該提案；不得當成功顯示。另一輪已完成。核心現在允許預算內修正一次引用／hash，但保留 REJECTED 任務；第二次失敗即停止。[Live 摘要與失敗](驗收證據/live-summary.json)

較早一轮還發現模型提到未確認的 CLI 開關，已加上「必須先有工程事實或 READ 原文」限制。這些修正及失敗可作为 Codex 根據實测改进可靠性的展示證據；不能宣稱模型從不出錯。

## 可獨立執行的命令

在 repo 根目錄執行，Linux 須具備 `binutils` 與 `squashfs-tools`：

```bash
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/python -m unittest discover -s tests -v

mkdir -p var
DEMO_WORK_DIR="$(mktemp -d var/demo-work.XXXXXX)"
tar -xzf demo-inputs/rom/03_rom.tar.gz -C "$DEMO_WORK_DIR"
.venv/bin/python -m cvevidence_core analyze "$DEMO_WORK_DIR" \
  --cve CVE-2014-0160 --mode OFFLINE \
  --output var/validation/rom03-offline.json

.venv/bin/python -m cvevidence_core analyze "$DEMO_WORK_DIR" \
  --cve CVE-2014-0160 --mode LIVE --env-file .env.local \
  --symptom '同事口述已關閉 heartbeat，請核對现有資料並指出補件。' \
  --output var/validation/rom03-live.json
```

不要把多個包解到同一個已有資料的目錄；正式 Runner 會建立新的 snapshot。直接用 tar 的命令僅供解包本 repo 已核對的 demo 檔，任意使用者上傳仍須走安全收件。

`scripts/validate_engineering.py` 驗九格、補件及核心反例；`scripts/validate_stability.py` 驗 30 次 OFFLINE；`scripts/validate_live_ai.py` 會真正使用 API 並累積費用，預設四個情境，亦可傳单一情境名稱。完整紀錄放 `var/validation/`。

## 界線與待整合

- Frankie 的 M5a 已接收件、原文與 delta 保存。完整分析入口、condition／InvestigationTask 映射、Live 狀態、報告與畫面仍需他整合；本次不冒稱前端全流程已驗收。
- 目前深度規則限三個已審查 CVE／格式及今日展示程式。未知／修改來源留下缺口；不宣稱可分析任意 ROM 或所有 CVE。
- Source hash 與編譯紀錄核對是內部一致性，沒有供應商簽章；`provenance_verified=false`。
- 正常測試未執行漏洞利用；工程適用性與事故根因／實際部署暴露分開。
- UI 應將 AI 正在調查、等待補件、引用拒絕、逾時與工程判定分開顯示。六分鐘 demo 可在 AI 執行時解說現有證據；備用 Replay 必須清楚標示。
