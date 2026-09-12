# 今日重製本機工作台
使用 Python 3.12，安裝 requirements.txt。從 repo 根目錄執行：
```sh
PYTHONPATH=src python -m cvevidence.cli --store var/runtime run input.zip --product TEST --cve CVE-2014-0160
PYTHONPATH=src python -m cvevidence.cli --store var/runtime list
PYTHONPATH=src python -m cvevidence.cli --store var/runtime show RUN_UUID
PYTHONPATH=src python -m cvevidence.cli --store var/runtime supplement RUN_UUID --note '待覆核文字'
PYTHONPATH=src python -m cvevidence.cli --store var/runtime report RUN_UUID
streamlit run runner_app.py --server.address 127.0.0.1 --server.port 8505
```
預設沒有核心，因此 run 回傳 CORE_UNAVAILABLE，exit code 2 並保存錯誤。
不能把測試用 adapter 啟用到正式展示，也不能宣稱已完成實際匯入或判定。
CVEVIDENCE_CORE_MODULE 只由操作者配置已審閱的 Python adapter 模組，不接受 UI 傳入。
可設定 CVEVIDENCE_STORE（預設 var/runtime）、CVEVIDENCE_ARTIFACT_ROOT（受控根目錄）。
目前上傳傳輸界限 20 MiB，正式大型樣品需由下一版 input reference 介面處理，不盲目放大記憶體上限。
工作台目前為 localhost 單人模式，尚未加入登入／per-run 存取控制，不對外建立 tunnel。
今日靜態 apps/web 不連接此工作台，只作 UX 模擬。
