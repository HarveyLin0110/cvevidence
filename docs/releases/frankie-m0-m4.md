# Frankie M0–M4 本機驗收
2026-09-12。分支 codex/frankie-fresh-milestones。
基線 origin/main 780dac1，未修改 docs/sync/Horace.md。

- M0：今日 UI 基線與團隊同步檔。沒有搬入舊 Python／舊 Demo。
- M1：共用契約 schema，9 tests passed。
- M2：隔離 worker、CoreAdapter、不可變保存、CLI，18 tests passed。
- M3：補件 parent、同宣告 build／既有 hash 保全、報告／原文引用，24 tests passed。
- M4：受控路徑、Streamlit 頁面、重載與補件操作，27 tests passed。
- 驗證命令：既有 Python 3.12 venv 的 python -m pytest -q；測試全部在今日新建 tests 內。
- 本機沒有安裝正式核心。測試明示 TEST_ONLY；實際無核心時回報 CORE_UNAVAILABLE。
- 沒有執行真實 ROM、CMake、curl、九格或 LIVE AI；M5／M6 尚未完成。
- 新 CI 只讀權限，Actions 固定已查得的 tag commit；CI 遠端結果另外核對。
