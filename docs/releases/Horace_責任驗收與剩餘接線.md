# Horace 責任驗收與剩餘接線

更新：2026-09-12 16:26。依 Frankie 雙人分工確認 DOCX、Champion Product Plan V5 與使用者後續修正核對；以當日新作為證據，不拿舊 Demo 成績代替。下方表格保留 14:38 checkpoint 的具名驗收，最新進度由本節補充。

## 最新實作與 Demo

- 正式網站已完成真實 CMake Live、同 build 補件、NI→Affected、報告與歷史回讀；不是仍未接 API。固定版本／run 見 [網站實測](團隊站_CMake_Live_實測_2026-09-12.md)。其當時尚缺的文字歷史接線已由 PR #20 合入 main。
- PC3 runtime-v2 由 PR #22 交付，三格式正常運作材料、命令／配置／gzip 核對、追加問題及補件保留。PR #23 的兩個初始 CMake 包實現「完整包直接查核」及「缺件包停在 AI 指引」，43／43 的三格式與歷史驗收、244 項測試及 23 subtests 已有具名紀錄，見 [Horace 同步](../sync/Horace.md)。
- #22／#23 已隨整合進入 main，#25 再加入 OpenSSL 完整情境；目前 main `063e581` 的預設是 OpenSSL 完整案例與 CMake 缺件案例。CMake 原兩包仍在 Git。展示 B 只說明如何補件，不要求現場真的補；講稿不列本輪優先工作。
- 本輪 PR #26 提供具體 PC 命中位置與最小補件清單，已合入上述 main；新實際 CMake Live 2 calls／24.883 秒、16／16，核心 hash 核對一致。呈現與交接詳見 [PC 命中細節與最小補件指引](PC命中細節與最小補件指引.md)。PR 合併、最新 CI 與公開網站發布仍須分開核對。
- 通用 CVE 調查由側邊 `codex/general-cve-triage` 開發，本分支仍只宣稱已有三個審查 profile 的正式判定能力。

產品 checkpoint 為 `7b24110`。其 PR #9 的 GitHub Actions **34678280555** 成功：**167 passed、23 subtests，45.22 秒**，含 schema 重產一致；此數為該 PR 與當時 main 的 CI 範圍。本機合回 main `9d11d48` 時 165 項通過，之後保存文字的改動另有 50 項聚焦測試及實際 Live。不同基準與測試種類分開記，不相加成漏洞通過率。

## 原分工與 plan 對照

| 需求 | 已提供的能力與實際證據 | 核對狀態 |
|---|---|---|
| 今天重新製作，舊內容只參考概念 | 新 builder／測試／程式；官方來源 lock、hash、授權；選定 ROM／CMake／curl r2 | 已提供；來源與建置在 tools/demo-data、data/catalogs |
| ROM：兩次建置、真映像、TLS 與備份還原 | OpenSSL 1.0.1f on/off、真 SquashFS／解包／正常 TCP TLS；來源到成品的取證規則 | 資料與工程驗收已通過 |
| CMake：兩版靜態連結與正常／錯誤觀測 | zlib 1.2.12／1.2.13、member/object/source 與產品 link/map 對應 | 資料與工程驗收已通過 |
| curl：同版官方修補前後 | 8.3.0、官方 backport、完整 header capture／164 library objects 與產品綁定、正常 SOCKS5 觀測 | 資料與工程驗收已通過 |
| 九包、三組同 build 補件、獨立 Git 輸入資料夾 | demo-inputs 的 12 包、SHA256SUMS、catalog／中文上傳表；12 hash 核對通過 | 已在 main，原 build 歷史留 var |
| 三種匯入、完整性、原文唯讀工具 | integrity／sources／frankie_adapter；Git archive 獨立 QA 九包及錯誤邊界 | 已驗；分析不執行上傳 binary |
| Q1–Q5 與 source/object/library/product 綁定 | queries／buildproof／evidence；每個案例實際產生五 query、條件與原文證據 | 九格工程 9/9 已有具名紀錄 |
| Evidence ID、原值／hash／範圍與 Verifier | 重取證比對、receipt、exact excerpt；篡改原值、ID、原文、混 context 拒絕 | 邊界測試及真包變體通過 |
| 三個 CVE profile、PC1／PC2／PC3 | CVE-2014-0160、CVE-2022-37434、CVE-2023-38545；逐條條件及共用前提，condition_groups 提供呈現語意 | 核心已交，PC 分組不代替規則 |
| 判定順序、範圍、衝突、舊 Claim | 完整 guard＋可靠阻斷才 Not Affected；全必要條件支持才 Affected；Claim 核對 build/artifact，未知不猜安全 | 九格、混版／多 ELF／文字／Claim 測試通過 |
| 現象與指定 CVE 兩入口 | 無檔案先 intake；有資料再候選；最多五 CVE 獨立處理，未知保留 unsupported | 核心測試通過，工作台入口由 Frankie 接入 |
| 真實 AI、動態追加問題與最小補件 | 四個原 Live 情境；ROM 同問題的預算修正重驗；新增未交付入口與延後啟動的 Live | 有真 API 記錄，不靠預寫答案 |
| AI 失敗不抹掉工程結果 | timeout、API 錯誤、無效引用、截止時間、一次修正仍共用原預算；保留失敗及已完成工具 | 單元、B 第二輪真 ROM 整合驗收通過 |
| AI 新原文回流 | SOURCE_OBSERVATION → 原文再核對 → collect/verify/assess；不把模型自由結論當工程條件 | ROM 實際新增 8 筆觀測；同 build 重判及篡改拒絕已驗 |
| 文字、材料補件與歷史 | 中性文字不誤阻擋；未決／矛盾／新範圍仍待查；同 build 新證據可解除歷史待查，M-ID／原 context 保留 | 三補件 3/3；C 第二輪 16/16，原輸入／結果未污染 |
| 延後啟動 AI 不遺失已保存補充 | investigator 自動帶入 bounded statement_context，優先未決及最近文字；仍標非工程事實 | 7b24110 空 user_context 的真實 Live 通過 |
| Live／Offline／Replay 區別與原時間 | 新 Live started_at／finished_at；Replay 保留原時間／record hash 並重核當次來源；舊時間缺失明示未知 | 真實 Live 及 Replay 核對成功、無模型重呼叫的單元測試通過 |
| 中文摘要、缺口、下一步與展示 | summarize、完整核心交件、六分鐘操作稿、評分項目與可驗收證據、中文選檔說明 | 內容已交；工作台組裝／下載由 Frankie 維護 |
| Python 模組、獨立 CLI、乾淨安裝 | 最新 core 以 pip 打包安裝，repo 外從 site-packages CLI 跑真 CMake 05：五 query、Not Affected、PC metadata；安裝 ai.py bytes 與工作樹一致 | 已驗，不只是從 src 直接 import |
| 共用格式與正式操作流程 | analyze_archive_for_runner、analyze_package、investigate_after_engineering、condition_groups 及 stage wrapper 接線說明；原 v0.2 收件保持相容 | 核心已交；正式 Live 保存／網頁聯合驗收仍待整合 |

## 可覆核紀錄

- [完整核心與九格／補件交件](Horace_完整核心與Demo交件.md)、[三個 CVE 規則範圍](../engineering/三個CVE規則與適用範圍.md)。
- [工程 9＋3 與五項對抗案例](驗收證據/engineering-20260912T052948.json)、[30 次 OFFLINE](驗收證據/stability-20260912T053053.json)、[真包變體](驗收證據/adversarial-real-packages.json)。
- [B 第二輪含成功與失敗](Parallel_AI_R2.md)、[C 第二輪回歸](Parallel_QA.md)。
- [ROM 預算修正 Live](驗收證據/ROM_AI預算修正Live摘要.json)：原 8 calls 耗盡保留；同問題修正後 5 calls、44.872 秒完成，Not Affected 不變。
- [新增入口 Live／Replay](驗收證據/新增入口Live與Replay摘要.json)、[延後 AI 保留歷史聲明](驗收證據/延後AI保留歷史聲明Live摘要.json)：後者 4 calls、31.198 秒，最小材料追問與既有工程保留。
- [D 指定版本的 consumer QA](https://github.com/HarveyLin0110/cvevidence/blob/754e6a3/docs/releases/Parallel_Contract.md)：基本資料及 scope 隔離通過，兩個 excerpts 呈現失敗；當時舊 Runner 未接分析，不能套用為新 main 狀態。
- [PR #9](https://github.com/HarveyLin0110/cvevidence/pull/9)、[7b24110 CI](https://github.com/HarveyLin0110/cvevidence/actions/runs/34678280555)。更新 head 後以新 checks 為準。

## 14:38 待辦的現況與剩餘聯合驗收

1. 核心、獨立 AI stage、scope 組合及原文呈現已接入 main；正式網站 CMake Live 及報告回讀已驗，不再標示未接線。
2. 最新 runtime-v2／两版 Demo 的正式網站操作須以整合端具名發布紀錄驗收。原 CMake 網站測試跨兩個部署版本，不能当成單一固定版本或受控服務重啟驗收。
3. PR #26 的細節呈現需整合端審閱、合併及发布後再核對。舊 AI 保存紀錄沒有核心收件清單時，仍顯示原始問題；必須新發起 AI 才會保存新格式清單，不能將舊紀錄改寫成新呼叫。
4. 原目標中的三格式核心、補件、保存與邊界驗收保留；現場不再走完整補件閉環。剩餘工作聚焦最新版發布、報告與歷史可讀，以及實測發現的問題。

上述剩餘項目屬整合與正式操作驗收；核心會配合處理發現的介面或語意問題。保留已完成的網站 Live 證據，也不將它擴張成最新版本所有流程都已驗收。

所有結論限定已審查的三 profile 與本次交付範圍。正常觀測不是漏洞利用重現；來源 hash 不是供應商認證；模型引用可核對仍不代表語意推論已證明。沒有用一次成功推估成功率或未量測的時間節省。
