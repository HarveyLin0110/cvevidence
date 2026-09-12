# 六分鐘 Demo 操作稿

此稿依今天已驗證的核心與輸入包設計；正式網頁按鈕和下載頁須由 Frankie 對應確認。HV 主講，實作者操作。真實 AI 有延遲，可在它執行時展開現有工程證據。

| 時間 | 操作與輸入 | 主講重點 |
|---|---|---|
| 0:00–0:30 | 顯示「描述現象」與「指定 CVE」兩入口 | 工程師常只有異常或掃描通知，欠缺可覆核的產品適用性證據。 |
| 0:30–1:30 | 指定 CVE-2014-0160，選 `demo-inputs/rom/03_rom.tar.gz`，啟動 Live | Q1–Q5 先指出缺口；目前不能用 1.0.1f 版本或「同事說已關閉」作完整判定。展開 ROM 成品 hash 與已取得的 linker 資料，等待 AI。 |
| 1:30–2:20 | 展開 AI 真正的新問題與 READ／SEARCH；再上傳 `rom/supplement_03_rom.tar.gz` | AI 要求同 build 的編譯／預處理與 libssl 綁定。補件生成新 context/run，原成品 hash 保持不變；條件實際阻斷後才轉 Not Affected。 |
| 2:20–3:30 | 現象入口：「更新匯入失敗，gzip stream ended before trailer」。選 `cmake/04_cmake.tar.gz`，由元件找 CVE 候選 | AI 讀正常與截短測試日誌，區分受影響程式路徑與本次 EOF；不要說這是成功漏洞利用。若需指定 CVE 的備援操作，用 CVE-2022-37434。 |
| 3:30–4:30 | 顯示 curl 09 缺件與 07 資料已完整的實測對照；可開目前 Live 紀錄，或清楚標示 Replay | 輸入不足時 ASK_USER；材料已提供時 READ 後完成，沒有固定第六題。正常 9-byte hostname 的成功下載未重現溢位。 |
| 4:30–5:15 | 九格工程表、三條補件前後比較；點一條 E-ID 到來源與原文 | ROM 同版本編譯不同、curl 同版本修補不同，展示工程取證的價值。數字只引用實測表。 |
| 5:15–5:45 | 展開一筆 INVALID_CITATION 拒絕紀錄，以及 compiler observer 修正紀錄 | 模型曾生成假 X-ID，被系統攔下；Codex 曾發現 libtool 標頭紀錄遺漏，修正後重建驗收。保留失敗提升可檢查性。 |
| 5:45–6:00 | 下載含成品、理由、缺口、Evidence ID 的中文摘要 | 結果可交給下一位工程師覆核；尚未證明部署暴露或事故根因時明確保留。 |

## 操作前準備

- 隊友從 `codex/horace-fresh-core` 最新版本取得 `demo-inputs/`，核對 SHA256SUMS；不必找舊 Demo，也不要各自重新打包。
- OpenAI 設定採 Sol／medium，前端須真的把設定交給 AI 執行階段。金鑰不顯示、不入 Git。
- ROM 補件選 `supplement_03_rom`；CMake 補件對 06；curl 補件對 09。不要拿另一個完整 build 當補件。
- AI 狀態与工程結果分開；若逾時或 API 失敗，展示真實停止原因。備用紀錄明確標 Replay，不宣稱正在呼叫。
- `docs/releases/Horace_完整核心與Demo交件.md` 有目前驗收數據；前端完整操作尚須 Frankie 彩排後才能稱為整體 demo 通過。
