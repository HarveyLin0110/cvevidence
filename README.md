# CVEvidence 今日從零實作

本次開發自零開始。先前規劃與 Demo 僅供概念、需求與展示情境參考；不複製或執行舊專案程式、建置腳本、測試、資料包及結果。

## 目前狀態

本目錄是今天唯一的開發與 Git 根目錄。全新 builder 與只讀核心正在製作；ROM on/off、CMake zlib 1.2.12/1.2.13、curl 修補前後已完成真實建置及正常功能測試。第一輪九包資料及三組補件驗收通過，15 項核心邊界測試通過。完整工程判定、九格與 Live AI 尚未完成。第一輪可呼叫的匯入/唯讀/補件核心見 [交件摘要](docs/releases/Horace_第一輪資料與核心交件.md)。

## 目前共同規劃

以 [Champion Product Plan V5](docs/CVEvidence_Champion_Product_Plan_zh-TW_V5_2026-09-12.docx) 為準，V4 保留供查閱。

兩條網頁入口分別支援現象描述與指定 CVE。深入查核先執行五個基礎 query，再由 AI 根據使用者資訊與證據自主追加查詢，或請使用者補件後接續分析。今日重建 ROM、CMake、curl 三種交付，每種各驗條件成立、有效阻斷與關鍵資料不足，合計九格目標。

產出位置及前端交接依 [產出存放與前端交接規劃](docs/architecture/產出存放與前端交接規劃_2026-09-12.md)：程式與規格進 Git，完整工程包放 `var/artifacts/`，每次分析放 `var/runtime/runs/`，下載報告放 `var/exports/reports/`。完整建置暫存在 `var/build/`，完成封裝後才進 `var/artifacts/datasets/`。

## 分工

以 Frankie 雙人分工確認文件更新 V5 的較早分工：

- Horace：三種新 builder、匯入/Query/Verifier、CVE profile 與判定引擎、AI 調查、補件驗證及驗收比對器。
- Frankie：contracts 主維護、正式 Runner/Web/CLI、不可變快照、補件保存與前後比較、整合。
- HV：報告、展示、今日實測成果與 Codex 使用過程整理。

各自維護一份同步文件：[Horace](docs/sync/Horace.md)；Frankie 的同步檔待他建立。評分與證據整理見 [評分項目與可驗收證據](docs/presentation/評分項目與可驗收證據.md)。

## 第一個交付目標

先約定最小輸入輸出格式，再從零做一條 ROM 情境的證據不足、補件、重新判定流程。Affected 必須有完整必要條件支持，不能以案例名稱指定答案。

## 目錄用途

- `apps/web/`：Frankie 的正式網頁，待整合。
- `src/cvevidence_core/`：今日產品共用邏輯，持續實作。
- `contracts/`：前後端格式與小型測試範例，待建立。
- `tools/demo-data/`：今日新寫資料建置程式與公開來源 pins。
- `tests/`：今日新寫測試。
- `scripts/`：啟動、資料取得、匯入與檢查腳本。
- `data/`：僅存資料 catalog 與取得方法，不存完整工程包。
- `docs/`：今日規劃與工作紀錄；V5 DOCX 暫留現有位置。
- `var/`：本機 artifact、建置暫存、run、完整驗收結果與報告，不進 Git。
- `outputs/`：既有空目錄；新產出依存放規劃分類，不再集中放入此處。

公開 OSS 依賴若有使用，須另記實際來源、版本與授權，不宣稱是團隊自行撰寫。
