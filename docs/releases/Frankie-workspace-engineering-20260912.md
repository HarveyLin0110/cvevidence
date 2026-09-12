# Frankie 工作台工程分析閉環交付

2026-09-12。基線：整合端70b3b68（Horace0a480df）。候選顯示直接採用441e49f的candidate_view.py及test_candidate_view.py，保留render_candidates介面。

## 實際接線

- 五步側邊導覽：輸入→範圍確認→工程分析→AI/補件→報告。未收件反灰，收件可分析／匯出，保存工程結果後才開啟AI頁；失敗可查看紀錄。
- 工程頁呼叫Runner.analyze_offline，選取保存的新child，再由Runner.read_engineering核對並呈現Q1–Q5、條件、缺件、工程初判與範圍。沒有從舊RunEnvelope.assessment猜結論。
- 無CVE收件可明確選候選或輸入一個CVE；已指定者不跨CVE分析。其他元件關聯與本次選取分開，FIX_RELEASE_VERSION不當安全結論。
- 報告使用正式payload；完整文字預覽收合，下載保留全文。條件使用摘要表與可展開引用。歷史列顯示CVE／狀態。
- 同build補件建立新收件run後回工程頁，重新分析；沿明確parent鏈找到上次工程結果，核對產品/release/build/artifact後顯示條件差異。原始資料不覆寫。
- workspace(st, *, store_root=None)保留，沒有變更team_app、帳號隔離或8507部署。

## 驗收證據

- 124 pytest passed（完整回歸，包含真實CMake AppTest按鈕閉環）；真實CMake06由NeedsInvestigation經補件再分析為Affected，父run bytes及原判定不變。
- scripts/validate_analysis_ui.py讀整合端正式CMake與curl保存紀錄：renderer、報告scope、報告／補件callback皆PASS。沒有新模型呼叫。
- 真實瀏覽器8506：ROM03建立請求99eb99a6-47c6-4da5-9687-26ef9c4c2637，收件ed0a02e2-9507-4612-aefe-8d3334ad5b6b；初分析fa2abecb-b570-46a1-b099-bdea2fdfb741顯示NeedsInvestigation／5queries；套用正式同build補件後，分析9cab656d-8035-40ba-aafe-682c76690a07顯示NotAffected，報告頁有補件前後工程結果。
- runtime及原始payload留本機，不進Git。UI動作與核心結果並非LIVE驗收。

## 尚待完成

獨立LIVE AI保存／可信任呼叫由整合端開發，尚未交付；AI頁明示OFFLINE，未假造建議。PC分組仍須profile正式提供，不沿用舊UI寫死對應。公開8507部署由整合端按固定SHA驗收後更新，本次僅8506開發服務。

對應D01/D02/D07/D08/D09及R01/R05/R06/R07/R08/R11/R12。來源文字安全呈現；工程與AI狀態分開；scope、parent与補件可追溯；未宣稱完整安全稽核或模型語意已驗證。
