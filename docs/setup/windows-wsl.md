# Windows 本機啟動（WSL Ubuntu）

工作台和工程分析引擎在 WSL Ubuntu 內執行，Windows 瀏覽器使用
`http://127.0.0.1:8505`。原始碼仍位於此 Git 工作目錄。
核心使用 `/usr/bin/readelf`、`/usr/bin/unsquashfs` 和 Linux 程序控制，
因此使用 Linux Python 虛擬環境。

## 日常操作

在專案根目錄的 PowerShell 執行：

```powershell
.\scripts\workspace-windows.ps1 start
.\scripts\workspace-windows.ps1 status
.\scripts\workspace-windows.ps1 restart
.\scripts\workspace-windows.ps1 stop
```

預設使用既有的 `Ubuntu` 發行版與 8505 埠；可透過 `-Distribution`、
`-Port` 指定其他值。服務在背景執行，不設定開機自動啟動。
原始碼更新後，使用 `restart` 重新載入。

## 首次安裝或重建環境

先在 Ubuntu 安裝 `python3-venv`、`binutils`、`squashfs-tools`。
接著在 PowerShell 的專案根目錄執行：

```powershell
wsl -d Ubuntu --cd "$PWD" --exec python3 -m venv .venv
wsl -d Ubuntu --cd "$PWD" --exec .venv/bin/python -m pip install -r requirements.txt
wsl -d Ubuntu --cd "$PWD" --exec .venv/bin/python -m pip install .
```

`.venv` 是 Linux 虛擬環境，請勿用 Windows Python 執行它。

## 資料與驗證

- 執行資料：WSL 的 `~/.local/share/cvevidence/<專案名稱與路徑雜湊>/runtime/`。
  實際路徑記錄於 `var/service/wsl-storage.json`。原碼與 Demo 包仍留在原 Git
  目錄；工程解包、證據核對與歷史保存使用 Linux 磁碟，以減少跨檔案系統 I/O。
  啟動程序若已設定 `CVEVIDENCE_STORE`，則沿用操作者的設定。
- 服務紀錄：`var/service/workspace-8505.log`。
- Python 依賴與服務紀錄由既有 `.gitignore` 排除；執行資料位於 Git 目錄外。
- 健康檢查：`http://127.0.0.1:8505/_stcore/health`，正常回應為 `ok`。
- 測試：`wsl -d Ubuntu --cd "$PWD" --exec .venv/bin/python -m pytest -q`。

完整測試中的 `test_statement_semantics.py` 會將暫存寫入原碼目錄的
`var/semantics-tests/`，在 Windows 磁碟上可能耗時很久。本次完整驗證使用
逐檔 SHA256 核對過的 Linux 原碼副本；核對清單與測試輸出分別保存在
`var/setup/linux-validation-source.json`、`var/setup/pytest-linux.log`。
實際兩個 Demo 的工程驗證結果保存在 `var/setup/demo-native-summary.json`。

## AI 狀態

本機啟動不自動啟用付費模型呼叫。Live AI 另需由操作者設定
`OPENAI_API_KEY`、`OPENAI_MODEL`、`OPENAI_REASONING_EFFORT` 和
`CVEVIDENCE_AI_ENABLED=1`；若使用私密設定檔，透過
`CVEVIDENCE_AI_ENV_FILE` 指向其 Linux 路徑。設定須由啟動服務的 Linux
程序繼承。金鑰不可提交 Git；呼叫仍需工作台中的外送同意。

此入口沿用 `runner_app.py` 的本機模式，只監聽 `127.0.0.1`。
團隊登入入口另見 `team_app.py` 與既有部署文件。
