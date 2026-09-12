# CVEvidence — 今日重製整合分支
以 2026-09-12 新寫的模組串接證據核心。工程初判待工程師覆核。
- [Frankie 同步](docs/sync/Frankie.md) / [Horace 同步](docs/sync/Horace.md)
- [里程碑紀錄](docs/progress/frankie.md)
- apps/web：今天製作、使用者確認可保留的模擬 UI；不是真實判定。
- src/cvevidence：今天新寫的共用契約、Runner、保存、CLI 與 Streamlit 整合。
- 不包含舊登入程式、舊 core.py、舊測試、舊 Demo 或任何工程包。
- contracts 的語意仍需 Horace 確認；正式 core adapter 尚未交付，預設明確拒絕分析。
- tests 的核心回應是今日建立的合成測試資料，不算產品漏洞驗收。

分支採短期 codex/*、每里程碑 commit、PR＋另一位成員覆核；不強推、不自動合併。
執行資料放忽略的 var/runtime，完整工程包不進 Git。
