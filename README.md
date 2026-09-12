# CVEvidence 今日從零實作

本目錄是 2026-09-12 唯一的開發、Git 與交付根目錄。舊 CodexHackathon／Demo 僅作概念與需求參考，不複製或執行舊程式、建置腳本、資料包及結果。公開 OSS 今日重新取得，保存來源、版本、授權與 hash。

## Demo 輸入與目前狀態

展示輸入集中在 [demo-inputs](demo-inputs/README.md)：9 個初始包、3 個同 build 補件、中文上傳對照表、catalog 與 SHA256SUMS，已納入 main。主展示先選 `rom/03_rom.tar.gz`，再補 `rom/supplement_03_rom.tar.gz`；補件須由補件入口提交，保留原 run。

Horace 的 Q1–Q5、Verifier、三個 CVE 規則、補件重判與 OpenAI 動態調查已實作。[PR #9](https://github.com/HarveyLin0110/cvevidence/pull/9) 交付完整核心；核心 checkpoint `44efc7b` 的 75 項測試通過，九格工程與三組補件、四種 Live 情境及 30 次 OFFLINE 穩定性已有紀錄。這些核心驗收與網頁全流程分開，接線進度見 [Horace 同步](docs/sync/Horace.md)、[Frankie 同步](docs/sync/Frankie.md) 及 [整合計畫](docs/integration/plan.md)。

Frankie 的共用 Runner、CLI、Streamlit 已接真實收件、原文操作與同 build delta；完整工程與 AI 顯示仍由整合端接入。`apps/web/` 是今日製作、使用者允許保留的模擬 UI；正式工作台入口是 `runner_app.py`。

## 規劃與分工

產品與展示以 [Champion Product Plan V5](docs/CVEvidence_Champion_Product_Plan_zh-TW_V5_2026-09-12.docx) 為準；分工依 Frankie 雙人確認文件更新。兩入口支援現象描述與指定 CVE；先查五項基礎 query，再由 AI 依本次證據追加調查或要求補件。候選、漏洞適用性與異常原因分開。

- Horace：今日 builder／輸入包、parser、Query、Verifier、規則、Claim、AI、補件語意與核心驗收。
- Frankie：contracts、正式 Runner／CLI／UI、不可變快照、保存、補件歷史、報告與接線。
- HV：簡報、展示與實測成果整理。

每人維護自己的同步 MD。介面見 [核心接線提案](docs/architecture/核心分析介面與接線提案.md)，評分證據見 [展示驗收對照](docs/presentation/評分項目與可驗收證據.md)。工程初判保留適用範圍與人工覆核；不以檔名、版本命中或 AI 意見指定答案。

## 安裝與執行

Linux 的真實 ELF／ROM 取證需要 `binutils` 與 `squashfs-tools`。

```bash
sudo apt-get update
sudo apt-get install -y binutils squashfs-tools
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install .
.venv/bin/python -m pytest -q
PYTHONPATH=src .venv/bin/python -m streamlit run runner_app.py --server.address 127.0.0.1 --server.port 8505
```

正式 CLI：`PYTHONPATH=src .venv/bin/python -m cvevidence.cli --help`。Horace 獨立核心 CLI：`.venv/bin/python -m cvevidence_core --help`。Live 由可信任執行階段讀取 `OPENAI_API_KEY`、`OPENAI_MODEL` 與 `OPENAI_REASONING_EFFORT`；金鑰不進 Git。

## 目錄用途

| 位置 | 用途 |
|---|---|
| `demo-inputs/` | 隊友與展示共用的 Git 輸入包及補件 |
| `src/cvevidence_core/` | Horace 取證、規則與 AI 核心 |
| `src/cvevidence/`、`runner_app.py` | Frankie 契約、Runner、保存與工作台 |
| `contracts/` | 共用 schema 與接線說明 |
| `tools/demo-data/`、`data/catalogs/` | 今日 builder、官方來源 pins 與成品索引 |
| `tests/`、`scripts/` | 測試、驗收與服務操作 |
| `docs/` | 今日規劃、協作摘要、展示與可公開驗收證據 |
| `var/artifacts/`、`var/build/` | 本機成品歷史與建置暫存，不進 Git |
| `var/runtime/`、`var/exports/` | 當次分析、歷史與匯出報告，不進 Git |

只有使用者指定的今日 demo 輸入例外納入 Git；客戶資料、秘密及 runtime 不納管。詳細見 [產出存放規劃](docs/architecture/產出存放與前端交接規劃_2026-09-12.md)、[AI 開發指南](docs/ai/README.md)。短分支透過 PR 審閱，整合負責人依既有授權與 main 門檻發布，不強推。
