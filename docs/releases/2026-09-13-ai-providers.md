# AIP 雙來源交付與驗收紀錄

日期：2026-09-13。PR：[31](https://github.com/HarveyLin0110/cvevidence/pull/31)。

雙來源程式已實作；Codex 本機路徑完成兩案 LIVE 自動驗收。M5 整體仍未通過：本機未設定 API Key／API model，API LIVE 及人工內容覆核保持 NOT_RUN。主 spec 維持「開發中」，不以單元測試或 Agent 覆核代替這兩項。

## 固定版本與範圍

- 原 main：`8e10efdaee1a814630e3d4c3cb5bdb0dcebf2092`。
- 完整測試與兩案 LIVE 程式：`bebb29988ada095116ebfc0b969e7f560939f226`；後續文件提交不改程式。
- 驗收來源清單 hash：`4d978adf3161e53e835b9b9f3e579e912102f4ab254d70d59de9b8d9a1a107cd`。
- Prompt hash：`8b6f11bac4f637eaf001a865c4fdf188fe52436252b4b0a45c6d0e22350a40d2`。
- CLI：官方原生 Linux `codex-cli 0.153.4`；政策／Adapter `codex-no-tools-v1`；設定模型 `gpt-5.6-sol`、推理 `low`，ChatGPT 認證，無 API Key。
- 原生 CLI 事件未提供實際回報模型，保存與 UI 顯示未知；不把設定模型冒充實際回報。

M0–M4 已交付 Provider 共用循環、API／CLI Adapter、v1／v2 保存分派、來源選擇與同意、錯誤／預算、歷史和操作文件。每筆 v2 request 保存 code／prompt／contract 版本，worker 前後比對，影響設定的變更使既有同意失效。

## 真實執行結果

僅使用已核准的 `fresh-demo-two-flows-v2`、`CVE-2022-37434`。每案 API／Codex 指向同一工程 parent；API 未設定所以沒有啟動 AI attempt。

| 案例 | 原工程判定 | Codex 自動驗收 | 結束動作 | 耗時 | 呼叫紀錄 | 輸入／輸出 token |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 完整受控材料 | AFFECTED | PASS | 4 次 READ → COMPLETE | 97.175 秒 | 5 | 56,368／3,352 |
| 缺動態觀測 | NEEDS_INVESTIGATION | PASS | READ、READ、SEARCH、READ → ASK_USER | 89.320 秒 | 5 | 57,277／3,008 |

第二案回報 cached input 2,432 tokens；第一案為 0。CLI 未提供 total_tokens，保持 null。表中呼叫紀錄是本次已完成收據數，不推論其他失敗 attempt 的計費，也不據此估算帳戶餘額或金額。

兩案均通過：至少一次來源工具、合法最後動作、PC1／PC2／PC3 摘要與引用、request／scope／原生收據、重新開啟 AI 結果一致、原工程 envelope／blob bytes 不變、archive hash 不變。驗收期間來源程式清單不變。

| 識別 | 完整材料 | 缺動態觀測 |
| --- | --- | --- |
| Archive SHA256 | `95c05f59d5aefc31807cfd38bc7c78b9ca5b00b210e9013cf5359e81420fd6e1` | `5dc5d7b25333b10b53e1aaeac9830dd3a25ecb9da3dd646787c49f783b0564b5` |
| Engineering run | `7082652c-d25a-42ec-ac50-36a70f2b0c91` | `735f99c3-c515-4576-b33f-4e074faf6737` |
| AI attempt | `8fd39e02-b2b6-41e4-9d8e-91a61f311311` | `5c0443fc-ddc1-4e27-a866-3c5e91afa94e` |

私有完整紀錄：WSL `~/.local/share/cvevidence/aip-live-20260913-1/`；本機安全摘要 `var/setup/ai-providers-live-summary.json`。原始模型內容、憑證及 runtime 不進 Git。

## 回歸、工具與審閱

- 完整 `python -m pytest -q`：**382 passed、23 subtests passed**，115.63 秒；一項刻意建立重複 ZIP 名稱的預期 warning。
- 使用原生 Linux venv 與逐檔 SHA256 一致的原碼副本。NTFS venv 的首次 Streamlit inspect.stack 導致 3 秒 AppTest timeout，改用原生 Linux 依賴後通過，沒有調高測試期限。
- 五份 schema 重新匯出後與提交版本一致；v1 schema 未改動。來源清單／測試輸出：`var/setup/aip-validation-latest.json`、`var/setup/pytest-aip-latest.log`。
- 真實瀏覽器完成核准包匯入、工程分析、Codex 可用狀態／帳務提示、未同意拒絕與 API 不可用停用按鈕；切換來源不自動呼叫模型。
- 已保存 LIVE 案例的真 Runner／AppTest／報告 QA：10/10 PASS，0.983 秒，維持預設 3 秒期限。歷史重選／rerun／匯出皆不重呼叫模型，原紀錄及輸入 hashes 不變；證據 `var/setup/ai-providers-saved-ui-review.json`。
- GitHub 程式 head CI：[34724788678](https://github.com/HarveyLin0110/cvevidence/actions/runs/34724788678)，SUCCESS；發布 gate 仍須核對 PR 最新 head。
- 受控本機假端點捕捉實際 CLI 請求 `tools=[]`，未帶 Authorization。這是 SIMULATED 工具政策驗證，另有最小 LIVE probe，兩者分開記錄。
- 真 Linux 程序測試包含超時、輸出超量、孫程序清理與 worker 遭 SIGKILL 的 parent-death 清理。
- 獨立 Agent 審閱修正了 provider allowlist、wrapper／認證／推理一致性、實際模型文案、readiness 原因與快取。內容覆核確認兩筆固定 LIVE 摘要與保存工程條件一致，沒有把受控 PC3 當成客戶部署、來源認證、漏洞利用或异常歸因；此為 Agent review，**不是人工核准**。

## AC 覆蓋與未完成

| 驗收 | 實際狀態 |
| --- | --- |
| AC-01、04、08、09、10 | 自動測試涵蓋來源選擇、不可用預設、同意失效、去重／失敗保留、舊紀錄及原生收據；兩案 LIVE 驗證實際保存與重開。 |
| AC-02 | Codex 兩案 LIVE PASS，無 API Key，包含來源工具與合法結束。 |
| AC-03 | 設定／缺件／認證／版本等負向測試通過；API 真實回歸 NOT_RUN。 |
| AC-05、06、07 | 共用證據與拒絕非法動作／引用、工具政策與程序上限測試通過；不宣稱全面防注入或自動语意驗證。 |
| AC-11 | Codex 同案例自動數據已記錄；API 比較與人工內容覆核 NOT_RUN。 |
| AC-12 | 全 pytest、schema、CI、實際瀏覽器與保存 LIVE 紀錄的 UI／報告讀取驗收通過；詳見上節。 |

尚待完整結案：操作者安全設定 API Key／model 後，以新輸出目錄執行兩來源 harness，補 API LIVE 與同案例比較；由人覆核最後提問、引用的支持關係及實際用途。未取得上述證據前，不能把整份 spec 改成已驗收。

本機工作台：`http://127.0.0.1:8505/`；設定與重啟見 [Windows／WSL](../setup/windows-wsl.md) 及 [Codex CLI](../setup/codex-cli.md)。切換 ChatGPT 工作區但 email／plan 不變時，操作者仍須更新 `CVEVIDENCE_AI_AUTH_REVISION`，此 hash 不是官方 workspace ID。

受影響規則：D01、D02、D04–D10，R01–R12。精確引用／雜湊不等於來源認證或語意充分；兩案 PASS 不推廣為所有 CVE／實體設備的成功率。
