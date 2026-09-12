# Horace 今日實作與驗收追蹤

依據：Frankie 雙人分工確認 DOCX（2026-09-12）、Champion Product Plan V5、Demo 白話說明。分工以 Frankie 文件為準：Horace 也負責判定引擎與 AI 調查；Frankie 維護正式 Runner、共用 contracts、Web/CLI 與保存。

## 來源邊界

今日團隊程式、builder、測試及工程包全數重新撰寫/建置。舊 DOCX 只讀需求；不讀取、複製或執行舊 Demo factory、產品 source、工程包或結果。第三方 OSS 從官方 HTTPS 重新取得，下載紀錄保存 URL、SHA-256、取得時間、版本與授權。公有來源不是團隊原創。

## 完成證據

| 必須交付 | 證明方式 | 目前 |
|---|---|---|
| ROM 真實 on/off 兩次 build、SquashFS 打包/解包、TLS/備份還原 | 今日完整建置紀錄、解包 hash、正常功能實跑 | TCP 新版 r2 的兩次 build/正常連線/資料驗收完成 |
| CMake zlib 1.2.12/1.2.13 靜態 build | link/map、正常 gzip/截短錯誤實跑、ELF | 兩版完成，資料 r2 通過 |
| curl 8.3.0 官方修補前後 build | patch、source/object/library 綁定、正常本機 SOCKS5 下載 | r2 兩版新建、正常下載、source/header/object/shared/tool 綁定完成 |
| 九包與三組同次補件、不可變 catalog/壓縮包 | archive/hash/lineage 驗收 | 九包與三組補件通過；新版 ROM r2 另驗通過 |
| 三種解析、Q1–Q5、原文工具、Evidence ID/Verifier | 真包驗收與篡改/混版/隔離測試 | 已提供；最新責任驗收表與 PR CI 記錄邊界、真包及整合範圍 |
| 三個 CVE profile/候選、確定性判定、Claim/缺口 | 九格實測；未知 CVE/多元件/衝突測試 | 九格 9/9；未知保留、未涵蓋 ELF 與衝突阻止安全判定 |
| AI 真實呼叫、動態工具/補件、引用驗證 | 至少三次 Live 紀錄；失敗/逾時/變體測試 | 四個情境完成；一筆假 X-ID 拒絕保留；逾時/429/假引用/越權工具測試通過 |
| 補件驗證/重新判定語意/摘要内容 | 三條補件及不同 build/文字聲明測試 | 三條補件重判通過；M-ID/Claim 與中文摘要完成 |
| Frankie Python 介面/CLI 驗收/交接包 | 從乾淨環境執行指令、schema 與真實範例 | 完整分析入口、中文接線文件、Git demo-inputs 及乾淨安裝驗收完成；Frankie 前端映射待整合 |

九格只填今日實測；建置、工程判定、Live AI 分開計數。分析器不執行匯入 binary、不讀 factory/test/validation/其他樣品或未提交補件。預期答案由獨立驗收端持有。

最新交件：[完整核心與 Demo](../releases/Horace_完整核心與Demo交件.md)。穩定性為三個主展示輸入各 10 次，共 30 次 OFFLINE；不冒稱整個前端已验收。

本表的第一輪數字保留原基準。最新逐項核對、已保存文字→延後 AI、PC 分組、Replay 原時間與正式接線待辦，請以 [責任驗收與剩餘接線](../releases/Horace_責任驗收與剩餘接線.md) 為準。
