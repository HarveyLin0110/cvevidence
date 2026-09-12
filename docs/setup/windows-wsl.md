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
原始碼或 AI 設定更新後，使用 `restart` 重新載入。

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

## AI 執行來源與本機設定

工作台可選 OpenAI API 或 Codex CLI；設定／登入只讓來源可用，按下調查並確認外送後才呼叫模型。Codex 使用後端 ChatGPT 帳號的額度，OpenAI API 使用操作者設定的 API 計費帳號。

在專案根目錄建立或編輯 **`var/config/ai.env`**。launcher 發現此檔且沒有明確的 `CVEVIDENCE_AI_ENV_FILE` 時會採用它；`var/` 已由 Git 忽略，設定檔與金鑰不可提交。

本機 Codex 設定範例：

```dotenv
CVEVIDENCE_AI_ENABLED=1
CVEVIDENCE_AI_PROVIDERS=openai_api,codex_cli
CVEVIDENCE_AI_DEFAULT_PROVIDER=codex_cli
CVEVIDENCE_AI_AUTH_REVISION=local-20260913
CVEVIDENCE_CODEX_BIN=/home/harvey/.local/share/cvevidence/tools/codex-0.153.4/codex
CVEVIDENCE_CODEX_HOME=/mnt/c/Users/ASUS/.codex
CVEVIDENCE_CODEX_MODEL=gpt-5.6-sol
CVEVIDENCE_CODEX_REASONING_EFFORT=low
```

此範例沒有 API Key；因此 OpenAI API 會顯示未設定，Codex 不會改用 API。CLI 的原生 Linux 版本、登入目錄與驗證方式見 [Codex CLI 設定](codex-cli.md)；其他電腦須換成自己的實際路徑。

若要啟用 API，在同一個忽略的檔案加入自己的設定：

```dotenv
OPENAI_API_KEY=<操作者自己的API金鑰>
OPENAI_MODEL=<該API帳號可用的模型>
OPENAI_REASONING_EFFORT=medium
```

尖括號是佔位文字，須替換後才能使用。完成設定後執行：

```powershell
.\scripts\workspace-windows.ps1 restart
```

重新開啟工作台，在「AI 執行來源」選擇來源、查看模型與費用歸屬，再確認外送。改來源、問題、設定、程式版本或案件會使舊同意失效。每筆 v2 調查保存 code／prompt／contract 版本，worker 前後核對；來源不可用時不自動切換。

若要改用其他設定檔，在啟動 **Linux 程序** 時明確指定，優先於 `var/config/ai.env`：

```powershell
wsl -d Ubuntu --cd "$PWD" --exec env CVEVIDENCE_AI_ENV_FILE=/home/harvey/.config/cvevidence/ai.env .venv/bin/python scripts/workspace_wsl.py restart --port 8505
```

`CVEVIDENCE_AI_ENV_FILE` 必須是 WSL 看得到的路徑。單獨設定 Windows PowerShell 的環境變數不等於已傳入 WSL；上例透過 `env` 明確傳入。檔案內的設定仍可由 Linux 程序同名環境變數覆蓋。

## 重跑 AI 流程驗收

從 WSL 的專案根目錄執行。直接執行驗收腳本不經 launcher，因此要明確指定設定檔：

```bash
export CVEVIDENCE_AI_ENV_FILE="$PWD/var/config/ai.env"
.venv/bin/python scripts/validate_ai_providers.py \
  --provider all \
  --output-dir "$HOME/.local/share/cvevidence/validation/aip-check-001"
```

不加 `--consent` 時只跑工程流程與 readiness，模型呼叫為零；兩來源的 AI 結果應是 NOT_RUN。操作者同意核准 Demo 資料外送後，另用新目錄並加入 `--consent` 執行真實調查，可指定 `--provider codex_cli` 或 `openai_api`。原始材料、收據與 summary 保留在指定 runtime，人工覆核另外記錄。完整 M5 結果以 [驗收與發布紀錄](../releases/) 為準。

此入口沿用 `runner_app.py` 的本機模式，只監聽 `127.0.0.1`。
團隊登入入口另見 `team_app.py` 與既有部署文件。
