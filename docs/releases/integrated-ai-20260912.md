# 最新核心與獨立 AI 整合驗收

2026-09-12，整合端。基線 main e9cc996；接收 Horace 9863b1b、Frankie c8c1128（功能25a39bf），整合程式 c278130。

## 實作與審閱
- 保留 main 的產品樣式、來源／候選範圍、登入隔離及歷史；不修改兩位作者的同步聲明。
- 獨立 AIRequest / AIOutcome 保存開始及結束收據；重複 ID 不再呼叫，缺結束收據不當成功，逾時殺掉程序群組。工程 run 不覆寫。
- 只在操作者啟用可信任配置且使用者同意本次外送時執行 LIVE；worker 僅取得必要 OpenAI 設定，不繼承 Google/GitHub 秘密。
- 使用核心 condition_groups 呈現共用前提與 PC1–PC3；不另算布林判定。舊紀錄沒有分組就明示缺少，禁止補造。
- 原文 excerpts 的 source、行號、文字、X-ID、file hash 同時出現在結果與文字報告；以 literal text/code 呈現，未宣称單純顯示即重新驗證。
- 審閱最新 statement 分句完整匹配、未知／新範圍仍待覆核、AI 失敗／引用修正預算、歷史聲明保存與模式識別。沒有新增第二套工程判定。
- 規則對應 D01/D02/D04–D10、R01/R03/R05–R12。不是完整 OS sandbox、語意認證、無限額保護或全面安全稽核。

## 真實合併版本驗收
- 純核心合併：167 tests、23 subtests；再合 F15：178 tests、23 subtests。
- PC／原文呈現及既有 renderer/report：15 tests 通過，含跨 CVE／未知條件與 HTML/Markdown literal 顯示。
- Git CMake06：archive SHA256 f49dce2610e68ddff8bf458173bcb15aaa4624d30ce9188f64e6d91feb061d54。
- 新工程 bf56ed65-6766-4280-bdc8-73c7cbb8f1c7，context d31f70a934e757d6b567202547ca1e42d223032185afae46e15ecf1510150a11。
- 新 AI c5703d5f-6096-4c9f-ad41-11912ffa0599：gpt-5.6-sol / medium，5 calls、34.365 秒、NEEDS_USER_INPUT。這是實際 API 呼叫，不是 synthetic response。
- 重新建立讀取程序，AppTest 讀保存 AI → 報告 → 同 build 補件 → Q1–Q5 重判；新 run 6d53ab2e-c480-4bfb-b17b-2a2672f717c5 為 AFFECTED，原工程與 AI 保持不變。
- 驗收腳本 scripts/validate_saved_ai_ui.py；完整模型／工程紀錄只留忽略的 var/integrated-ai-acceptance，不提交金鑰或 runtime。

## 部署門檻與未完成
公開站固定 SHA 的 CI 成功後部署；保留 OAuth allowlist、每帳戶隔離、備份與前版回復。公開站 LIVE 點擊與重啟驗收結果另補 PR 留言，不能以本機成功代稱已發布。
Replay 核心已交但尚無獨立產品操作入口；尚未提供 UI 取消與跨使用者總費用上限。每次程序180秒、核心90秒／8calls仍有效；此結果不代表所有情境固定成功或固定延遲。
