# 通用 CVE 調查入口

2026-09-12，獨立分支 `codex/general-cve-triage`，基線 main `063e581`。

## 解決的問題與範圍

原流程只接受三個已審查 CVE，其他編號在收件後直接停止，assessment／AI 均為 null。新版讓其他有效格式的指定 CVE 進入材料盤點、公開公告取得、Q1–Q5 查核計畫及既有 Live AI 調查入口。使用者結論為「需要進一步調查」，同時明示「已完成材料盤點，漏洞條件驗證尚未執行」。

這是通用調查能力，不是任意 CVE 都能自動出具工程適用性證明。既有三個專用 CVE 的規則判定保留；新 CVE 的條件目前全部 UNKNOWN，AI 自由文字、公告、版本與檔名都不能升格成已驗條件。要支持 Affected／Not Affected，仍需有可覆核的必要條件與工程驗證。

收件仍使用目前工具可接收的工程包；沒有在此變更加入任意原始韌體格式、OCR 或 PCAP 深入解析。無指定 CVE 的自動候選發現仍限現有元件目錄，不能稱已全面搜尋所有 CVE。

## 介面與狀態

- `analyses[].assessment.assessment_kind = GENERAL_TRIAGE`。
- `inventory_status = COMPLETED`；`cve_condition_verification_status = NOT_RUN`；verdict 固定為 `NEEDS_INVESTIGATION`，各必要條件 UNKNOWN。
- 外層 `engineering_status = COMPLETED` 表示盤點與保守缺口評估已完成，**不是漏洞條件已完成驗證**。收件或系統失敗仍走原 FAILED／TIMED_OUT，不產生這份結果。
- `queries[].status = AWAITING_RULE_REVIEW`，`metadata.gap_kind = CAPABILITY_GAP`。這些是工具查核能力缺口，不全部推給使用者缺件。
- 新增 `public_cve_record`：固定公開來源、取得時間、原始 JSON bytes／SHA256／PUBLISHED、REJECTED、RESERVED、UNAVAILABLE 狀態。
- 新增 `query_plan`：每個問題的 PC、目的、材料種類、已定位檔案與數量、待開始／可先查閱／待定位或補件狀態。檔案分類只供排程，不表示內容已驗證。
- 延後 AI 使用當次保存的公開紀錄，不在重讀歷史時重新抓網路。仍需原本的 AI 啟用設定與使用者外送同意，保留獨立 AI run、工具紀錄、父結果及期限。
- 歷史 `UNSUPPORTED_CVE` 繼續可讀；畫面說明它是舊版未執行紀錄，提示從原收件重新分析。沒有改寫舊結果。

## 公開資料與外送

固定 API：`https://cveawg.mitre.org/api/cve/<validated-CVE-ID>`。只外送 CVE ID；不發送產品包、使用者情境或金鑰。最多讀 1 MB，連線 timeout 8 秒，拒絕 redirect，不追蹤公告內參考連結，不接受任意 URL。父 worker 仍控制整次 deadline。

`OFFLINE` 仍表示不呼叫模型；通用 CVE 的公開查詢與模型呼叫分開，執行前畫面說明此公開查詢。需要完全離線時，操作者可設定 `CVEVIDENCE_PUBLIC_CVE_LOOKUP=0`；會明示公開資料不可用，仍可盤點及列計畫。未取得公告不是 CVE 不存在，更不是產品安全。

## 分工與合併

新邏輯主要在 `general_triage.py`、`public_cve.py`、`general_triage_view.py`。其餘只加入口、保存驗證與畫面接線。沒有直接修改主對話工作目錄、網站服務、部署設定或 Demo 輸入包。

已通知「比賽進行時」由此分支負責通用 CVE；PR #26 的 PC 命中細節與最小補件仍由原作者維護。共用交會點為 `ai.py`、`analysis_view.py`、`analysis_report.py`，整合時保留兩邊新增內容，不整檔覆蓋。

## 驗收

- 新增公開來源的編號／hash／大小／錯誤／redirect 邊界測試。
- 新增一般 CVE 未知判定、防偽造條件、公開資料作低信任輸入、已提交資料 READ、延後 AI 不重抓、UI／報告呈現測試。
- 可重跑真實流程：`python scripts/validate_general_cve.py --output <new-local-output> --live --env-file <operator-env-file>`。
- Live 使用真實 CVE-2024-1179 公開公告及今日 CMake demo，**明示 demo 不是 TP-Link 韌體**。AI 應追問產品對應與證據，不因名称不同判安全。
- 首次 Live：gpt-5.6-sol，5 calls，44.276 秒，NEEDS_USER_INPUT；具體 READ／SEARCH／ASK_USER，重核仍待調查，10/10 保存與範圍檢查通過。完整本機收據在 Fresh 的 `var/validation/general-cve-live-01/`，不提交 API 完整輸出或私有執行資料。
- 最新使用者要求「不要再完整測試了」：已中止完整回歸，不再重啟或讓 CI 重跑全量。提交使用 `[skip ci]`，由整合端依已授權的聚焦證據審查，仍遵守實際分支保護。
- 聚焦驗收：31 項核心／通用入口／Query 準備通過；最終必要的 15 項通用調查與 UI 檢查通過（5.16 秒），schema 重產沒有差異。測試集合重疊，不能相加成總數。
- 中止前完整回歸記錄為 241 passed／4 failed／23 subtests；四個畫面案例被執行中程式變動觸發的版本指紋保護擋住，程式停止變更後全部包含於上述 15 項重查並通過。不宣稱完整回歸成功。
- 首次 Live 的來源 hash 清單隨本機收據保留；其後只调整通用條件標題、歷史聲明的來源欄位保存與入口按鈕文字，聚焦檢查使用最終程式。未宣稱首次 Live 在後來的 Git commit 上重新執行。

對應開發規則 D01–D10；主要 runtime 規則 R01–R03、R05–R12。R04 擴充為先盤點五類查核與其真實執行狀態，再追加具體問題。R07 保留執行失敗與漏洞判定分離，新增已執行盤點的保守 triage 結果，畫面與報告都明示 CVE 條件尚未驗證。
