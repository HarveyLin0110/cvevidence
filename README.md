# CVEvidence — 今日重製整合分支
以 2026-09-12 新寫的模組串接證據核心。工程初判待工程師覆核。
- [Frankie 同步](docs/sync/Frankie.md) / [Horace 同步](docs/sync/Horace.md)
- [里程碑紀錄](docs/progress/frankie.md)
- [AI 協作、安全邊界與亮點指南](docs/ai/README.md)
- apps/web：今天製作、使用者確認可保留的模擬 UI；不是真實判定。
- src/cvevidence：今天新寫的共用契約、Runner、保存、CLI 與 Streamlit 整合。
- 不包含舊登入程式、舊 core.py、舊測試、舊 Demo 或任何工程包。
- Horace 核心已合入：真實匯入、候選探索、list/search/excerpt/compare、同 build delta 補件已接到共用 Runner 與 Streamlit。Q1–Q5、正式判定、AI 仍 NOT_RUN。
- [實際接線驗收與操作](docs/releases/Frankie-core-integration-20260912.md) / [Horace 原始交件](docs/releases/Horace_第一輪資料與核心交件.md)
- tests 的核心回應是今日建立的合成測試資料，不算產品漏洞驗收。

分支採短期 codex/*、每里程碑 commit、PR＋另一位成員覆核；不強推、不自動合併。
執行資料放忽略的 var/runtime，完整工程包不進 Git。

安裝：`python -m pip install -r requirements.txt`。
啟動：`PYTHONPATH=src python -m streamlit run runner_app.py --server.address 127.0.0.1 --server.port 8505`。
CLI 真實收件：`PYTHONPATH=src python -m cvevidence.cli --store var/runtime import var/artifacts/archives/<revision>/<package>.tar.gz`。
CLI 補件：`PYTHONPATH=src python -m cvevidence.cli --store var/runtime delta <parent-run-id> --package <supplement.tar.gz>`。

核心在 `src/cvevidence_core/`，整合在 `src/cvevidence/`；builder 與來源 pins 在 `tools/demo-data/`。分析器不執行匯入成品。
