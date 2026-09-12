# Queries 與 Horace runtime-v2 整合

2026-09-12，Frankie 整合。基線 main 7cd00e6；Horace PR22 固定交付 c6bdf9ff9cbcbba7d1244edb0b3a4c559636f73a。本次包含核心變更與 UI 相容性，發布狀態以本 PR 的 CI／部署紀錄為準。

## Horace 改了什麼

| 面向 | 先前 | 新版 |
| --- | --- | --- |
| PC2／PC3 | PC3 主要呈現程式輸入路徑 | 靜態路徑歸 PC2；PC3 另外核對同成品運作收據、原始輸出、樣本／配置 |
| 工程條件 | 四共用＋PC1一＋PC2一＋PC3二＝八 | 四共用＋PC1一＋PC2三＋PC3一＝九；新增 runtime_observation |
| Queries | 起始工程查核 | 目前起始查核仍有五個，但會依缺口追加 DQ-ID 問題；收到收據後可再要求它引用的材料 |
| 問題狀態 | 容易把動作完成當成查核完成 | RULE_GAP 和 MODEL 分開；等待用戶、等待交叉驗證、已驗證、拒絕分開 |
| 補件 | 工程 source／build 補件 | 新 runtime-only delta 不換 binary／library／source，保留父 run；比較問題新增與狀態變化 |
| 材料驗證 | 靜態取證為主 | 核對命令與材料 path、成品 hash、gzip 完整性／CRC／輸出長度，以及已審查配置／正常操作格式 |

新增 ROM／CMake／curl 共六包 runtime-v2。新版標準靜態包會先 Needs Investigation，補齊同成品運作證據才可支持 Affected；有效修補阻斷仍可在未做運作觀測時支持 Not Affected。不把檔名或情境描述當答案。

此處的觀測是 CONTROLLED_LOCAL_OBSERVATION，不是客戶實機來源認證、漏洞利用重現或異常根因。解析器不執行使用者上傳程式／命令。原 PR20 的歷史聲明保存仍保留。

## 本輪前端接線

- 按鈕統一「執行 Queries 與正式判定」，移除頁面上固定 Q1–Q5／五項文案。
- 依使用者最新要求，結果摘要移除「這份結果能回答什麼」與「五項查核告訴我們什麼」；查核細節集中在 Queries 分頁，PC 摘要與下一步保留。
- 「Queries 執行紀錄」依本次保存的 Query ID 列出名稱、用途、PC 層級、狀態與原文；新增 ID 不再被固定五項白名單隱藏。沒有保存的項目不補造已執行紀錄。
- 優先使用保存 title／description／metadata；已知 v2 有簡要用途。舊 Q5 不套用新版 PC3 說明。
- 規則追加問題與模型調查保持不同来源／狀態，等待補件不列為已驗證。
- 兩個情境輸入改用 src/cvevidence/demo_scenarios.py 的完整背景、疑問、交付／缺少材料及輸出要求。模擬業務背景明示，不冒充真實客戶事件。
- 結果與報告頁可展開「本次情境描述」；情境、原始快照與補件歷史不丟失。
- 舊 profile 的工程／AI 歷史可查閱，但前端停止在它上面啟動新版 Live，提示從原始收件／補件重新分析。避免不同版本 verifier 混用。

## 主 Demo 更新

A：新版完整材料查核。同成品 static＋runtime 材料實際取證後 Affected，展示 PC1／2／3 支持條件。

B：新版缺少運作材料。先 Needs Investigation，PC2 與 PC3 明確區分；依追加 Queries 補 runtime delta，再重新查核、比较前後。公開 B 保留在待補件階段供現場操作。舊 A/B 保留，不能把舊版八條件的 Affected 當成新版已驗收。

## 驗收紀錄

- 六包 SHA256SUMS 6/6 通過。
- 真實新版兩情境／多 CVE／報告隔離／補件／請求往返 AppTest 通過。A request 1ee96bb0、engineering 3a6b728b；B request b63687ba、原工程 d413edec、補件工程 e96762dd，原檔保留，零 LIVE 呼叫。
- 新增未來 Query ID、保存用途、原文 literal、重複 Query 不任選結果、舊 profile AI 停用的回歸測試。早期測試固定假設五列而失敗，已隨「只顯示實際保存項目」的規格修正；未變更真實工程結果來符合测试。
- Full pytest／schema／CI 的固定 head 結果與公開驗收寫 PR 留言。Horace 先前具名 Sol Live 五次呼叫屬 ca55381 的交付驗收；本輪不冒稱重新執行付費模型。

安全規則：D01／D02／D04／D06／D08／D09，R01／R04／R06／R07／R08／R11／R12；輸入與 AI 文字不是命令或工程事實，輸出保持 literal，scope／不可變歷史／失敗狀態不放寬。
