# Codex CLI 執行來源設定與驗證

更新：2026-09-13。對應 [AIP spec](../specs/ai-providers.md) 的 M0／M3、AC-02／03／06／07／10；D04–D06、R01–R03、R08–R10。以下 Adapter／程序測試與最小 LIVE probe 不代表完整 CVE 調查或雙來源 UI 已验收。

## 執行環境

第一版限定原生 Linux CLI **0.153.4**。Windows 瀏覽器可繼續使用，但 WSL 後端不接受 `codex.exe` interop。版本不同會回報 `CLI_VERSION_UNSUPPORTED`；升級時先重驗工具目錄、事件契約及程序清理。

本機已將 OpenAI 官方發行檔安裝至：

```text
/home/harvey/.local/share/cvevidence/tools/codex-0.153.4/codex
```

發行來源：`https://github.com/openai/codex/releases/download/rust-v0.153.4/codex-x86_64-unknown-linux-musl.tar.gz`

壓縮檔 SHA256：`f479424eca092484dc40d87ae28c44f4cc40234a60045d6131e493800d814a30`，下載後與官方 release metadata 核對。未改 Windows Codex 或全域 PATH。官方另提供 [Linux 安裝入口](https://learn.chatgpt.com/docs/codex/cli)。

## 操作者設定

設定入口是 AIService／ai_config 的環境變數，網頁不能傳任意 CLI 路徑或模型。在專案根目錄編輯忽略的 `var/config/ai.env`：

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

此範例沿用本機路徑；其他電腦須換成實際 Linux CLI 與操作者登入目錄。未填 `OPENAI_API_KEY`／`OPENAI_MODEL` 時，API 選項會不可用，不影響已配置的 Codex；只要 Codex 時也可將允許來源設為 `CVEVIDENCE_AI_PROVIDERS=codex_cli`。

Windows launcher 會自動採用存在的 `var/config/ai.env`，明確指定的 `CVEVIDENCE_AI_ENV_FILE` 優先。直接在 WSL 執行 Python 或驗收腳本時先設定：

```bash
export CVEVIDENCE_AI_ENV_FILE="$PWD/var/config/ai.env"
```

修改後在 Windows PowerShell 執行 `.\scripts\workspace-windows.ps1 restart`，操作細節見 [Windows／WSL 啟動](windows-wsl.md)。服務環境中的同名設定會覆蓋設定檔；不要將設定檔或憑證放進 Git。

`CVEVIDENCE_CODEX_HOME` 指向操作者已有且可信的登入目錄。此本機的 Linux 預設 `~/.codex` 未登入；官方 Linux CLI 可以讀原有 Windows 登入目錄並確認 ChatGPT 模式，沒有複製或解析憑證。若另建個人 Linux 登入，在 WSL 使用官方 CLI：

```bash
CODEX_HOME="$HOME/.codex" /home/harvey/.local/share/cvevidence/tools/codex-0.153.4/codex login
CODEX_HOME="$HOME/.codex" /home/harvey/.local/share/cvevidence/tools/codex-0.153.4/codex login status
```

完成後將 `CVEVIDENCE_CODEX_HOME` 改為該目錄的實際絕對路徑；設定檔不執行 shell，也不展開 `$HOME`。本版身分核對要求官方 CLI 的檔案式認證入口。

`CVEVIDENCE_AI_AUTH_REVISION` 是操作者設定版本；更換登入 profile、ChatGPT 工作區或帳務範圍時更新並重新同意。官方 `account/read` 目前回報 type／email／planType，Adapter 只將其 SHA256 回傳後端作設定身分，不保存 email 或 token，也不把此 hash 顯示為官方 workspace ID。相同 email／plan 的工作區切換仍依操作者更新 revision。

`codex_readiness(config)` 不呼叫模型：检查 ELF、版本、官方 `login status` 的 ChatGPT 模式，再經官方 app-server `account/read(refreshToken=false)` 核對身分。無法取得身分就不可用；不以讀 token、推測 email 或 API Key 替代。此結果不保證帳號仍有額度。

UI readiness 使用 15 秒記憶體快取，鍵包含 CLI／auth.json 的連結與目標 stat 身分、操作者模型／認證 revision／目錄及政策版本；不讀取憑證內容。檔案原子替換或設定變更即失效，回傳副本避免 UI 改動污染快取。readiness 預設期限 8 秒；實際每個 `step` 使用 `force_refresh=True` 並受剩餘期限收緊，核對到身分變更時拒絕繼續。`--version`、`login status` 與 `account/read` 都使用臨時認證 home，不載入原 home 的 config／hooks。

每筆 `AIRequestV2.versions` 必填 code SHA256、prompt SHA256 與 `contract_version="2.0"`。`config_id` 包含這些版本，worker 在調查前後重新核對，payload／request 必須一致；原始碼改變後請重啟服務、重新選擇並同意。這項檢查提供內容版本追溯，不是來源認證或模型結論正確的證明。

## 執行限制

每次 readiness 身分核對及每個調查步驟建立獨立臨時目錄。目錄內只放受控指令、schema、最小模型目錄及指向原 `auth.json` 的認證符號連結，由官方 CLI 讀取；Python 不開啟其內容。新 `CODEX_HOME` 不帶個人 config、MCP、插件、skills 或其他案件；finally 清理臨時狀態，原登入檔保留。

ModelInfo 目錄是本應用的執行政策：`shell_type=disabled`、`apply_patch_tool_type=null`、experimental tools 為空。再以固定參數關閉 shell、MCP、apps、plugins、hooks、瀏覽／影像／委派等工具，停用個人規則與專案文件注入。只有 Python 會執行 LIST／SEARCH／READ／COMPARE／VERIFY。

0.153.4 的 `unified_exec` 可能仍顯示 true；官方該版本工具裝配程式另外要求 `ShellTool=true` 才註冊 shell，故不把單一 feature 顯示當工具驗收。驗證腳本以全新空認證及本地假 Responses 端點捕捉實際請求，確認 `tools=[]` 且沒有 Authorization，再做獨立真實 probe。`model_catalog_json` 為 [官方設定項](https://learn.chatgpt.com/docs/config-file/config-reference)。

限制預算：輸入 256 KiB、stdout＋stderr 2 MiB、單一事件 256 KiB、最終訊息 128 KiB；模型、readiness、程序啟動共用呼叫者剩餘期限。輸入只走 stdin，來源文字不插入 shell 指令或高權限 instructions。

Linux supervisor 使用 parent-death signal；deadline、輸出超限、正常結束後都清理專屬程序群組。專項測試覆蓋真正子程序、孫程序及 worker 遭 SIGKILL 的情境。此政策沒有授權模型產生任意程序或另建 session。

## 重跑驗證

在 WSL 專案根目錄執行（使用已安裝相依套件的 Python）：

```bash
export CVEVIDENCE_AI_ENV_FILE="$PWD/var/config/ai.env"
.venv/bin/python -m pytest -q tests/test_codex_provider.py tests/test_ai_provider_core.py
.venv/bin/python scripts/validate_codex_provider.py \
  --bin /home/harvey/.local/share/cvevidence/tools/codex-0.153.4/codex \
  --codex-home /mnt/c/Users/ASUS/.codex \
  --model gpt-5.6-sol --auth-revision local-20260913 \
  --output var/codex-readiness.json
```

加入 `--live` 才會明確執行一個無客戶材料的最小模型 probe、消耗 Codex 額度。腳本先驗證本地工具目錄，失敗則不執行 LIVE。JSONL／schema 使用方式依 [OpenAI Docs](https://learn.chatgpt.com/docs/non-interactive-mode)。

2026-09-13 本機實測：本地 capture 取得 1 個請求，tools 空且未攜帶認證，PASS。隔離認證的真實 probe 收到 ASK_USER、原生 thread ID、turn.completed 與 exit code 0，input 402／output 176 tokens；實際模型名稱未出現在事件，收據保存 null，設定模型為 gpt-5.6-sol。執行紀錄只留忽略的 `var/codex-live-final.json`。

原生事件包含未知工具、缺失終結事件、非法 JSON 或超限時均拒絕成功；不偽造 API response ID。測試捕捉的預期 HTTP 400／程序退出 1 是 TEST_ONLY 截取終止，不能稱 LIVE 成功。完整調查、引用、不可變保存與 UI 驗收由整合流程另外執行。

兩個核准 Demo 的完整 Runner 驗收使用共同設定入口：

```bash
export CVEVIDENCE_AI_ENV_FILE="$PWD/var/config/ai.env"
.venv/bin/python scripts/validate_ai_providers.py \
  --provider codex_cli \
  --output-dir "$HOME/.local/share/cvevidence/validation/aip-codex-001"
```

不加 `--consent` 時模型呼叫為零，AI 部分為 NOT_RUN。要執行真實調查，操作者須在上述指令加入 `--consent` 並使用新目錄；兩來源比較改為 `--provider all`。腳本的自動 PASS、FAIL、NOT_RUN 與人工覆核分開，calls 表示呼叫嘗試紀錄而非已計費保證；M5 的實測／人工結果由 [驗收與發布紀錄](../releases/) 留存。
