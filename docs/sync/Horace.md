# Horace 開發同步

## 2026-09-26 MiniZip 自主原碼查核

- 4aad581：CVE 參考中的 GitHub PR 固定映射至 patch-diff 原文，保留出處／hash、去重與順序，沿用下載界線。b0abb72：明確修補副本未編入不等於產品排除，缺少成品材料不等於產品不存在；屬提示強化，不宣稱完整語意驗證。
- 來源聚焦 27 passed，最終全量 634 passed、23 subtests passed（272.89 秒）。上輪 CI 36212573362／36212597056 成功，本輪待執行。
- 新製 TEST_ONLY zlib 1.3-vendor1 清單＋上游固定 v1.3.1 zip.c，無成品與建置。無工具步驟指示的 LIVE 首次 ed8bb7cc 找出修補但收尾有不妥停止推論；提示修正後 ea19b367：7 calls、122.08 秒、151797 tokens，具體讀出四項 0xffff 防護並保留建置／其他副本缺口。一次 COMPLETE 被既有補件 guard 拒絕後 ASK_USER 完成，只要求一份 link map／manifest。
- 實連 8506 核對行號與補件卡。詳見 docs/releases/2026-09-26-MiniZip自主原碼查核.md；只推個人分支。真實產品建置驗證、跨案例穩定性與公司內網部署仍待完成。

## 2026-09-26 保存公告搜尋與閱讀

- d32d930：SEARCH_PUBLIC／READ_PUBLIC 只查本輪保存公告，核對文字 hash、不連網、不產生產品 X-ID；公告保存上限 12 萬字元、初始選段仍 6000，讀片段 200 行／8000 bytes。完整回歸 624 passed、23 subtests passed（305.73 秒），聚焦 42 passed。
- 指定公告工具能力驗收 LIVE 125d9536：實際搜尋、讀取 Debian 保存行 65–85，再完成 PC 查核；7 calls、80.03 秒、100947 tokens、零步驟失敗，最後僅一份 manifest 補件。明確不把 Debian 修補版本套到 vendor1；仍是 TEST_ONLY 材料與 NEEDS_USER_INPUT，非完整漏洞驗證或自主選工具評測。
- 已實連 8506 核對結果，詳見 docs/releases/2026-09-26-保存公告搜尋與閱讀.md。上輪 CI 36212050738／36212073546 成功，本輪 CI 待執行；只推個人分支。自主深度查核、完整觸發條件與可信建置仍需補強。

## 2026-09-26 CVE 補充公告來源

- 852c449：有界合併 CNA／ADP 參考與出處，維持 CNA 描述／版本；Debian security／LTS 固定訊息路徑可讀，三份來源／六次嘗試／十五秒共用。c395d28：來源出處、下游範圍、未支援與未訪問清單。
- 九項新增測試，聚焦 21 passed；完整 612 passed、23 subtests passed（277.48 秒）。上輪 CI 36211465448／36211484541 成功，本輪 CI 待執行。
- 同 TEST_ONLY BusyBox 材料 LIVE e59027fa：5 calls、76.85 秒、71921 tokens，六項條件，零失敗步驟；實際新增取得 Debian ADP 公告，要求實際設定與建置收據兩項同缺口材料。未誤套下游修補版本，但條件仍全引用 CNA，不宣稱已深入驗證觸發條件。
- 實連 8506 核對來源面板；原輸入與 AI 收據仍可驗證。詳見 docs/releases/2026-09-26-CVE補充公告來源.md。只推個人分支，完整漏洞語意、可信建置、更多 ROM 與公司內網部署仍待補強。

## 2026-09-26 AI 背景工作記憶體回收

- 689b8ac：完成 Future 不再持有完整 AI 結果或例外堆疊；最多保存 128 筆精簡完成狀態，保持整個服務兩個執行中工作的限制與工作區識別。保存紀錄不刪除，舊狀態 UNKNOWN 不自動重送。
- 新增五項生命週期測試；首次全量發現新測試等待 helper 的競態，修正後全量 603 passed、23 subtests passed（257.42 秒）。沒有更動 Runner、判定或 AI 設定。
- 實際背景工作 206d853b 保存 CONSENT_REQUIRED，無模型呼叫，網頁 8506 可查看；新程序重新提交同 ID 仍讀回相同收據。詳見 docs/releases/2026-09-26-AI背景工作記憶體回收.md。
- 上輪 CI 36210777136／36210819246 成功，本輪 CI 待跑；只推個人分支。下一步需加強新 CVE 公開細節來源與真實材料判讀、公司部署仍未完成。

## 2026-09-26 BusyBox 跨案例查核

- 8b2cc98：品質量測分開原文可用、成功 READ、條件引用及動作失敗，不將引用覆蓋誤稱讀取覆蓋。聚焦 3 passed；完整 598 passed、23 subtests passed（262.55 秒）。
- 新建 TEST_ONLY BusyBox 清單／設定，LIVE 6f56be0f：Sol/high，75.64 秒、5 calls、61221 tokens，七項 PC 條件，零失敗步驟。辨識 ash 關閉但未綁成品，只要求一份建置對應紀錄；未判安全、未重索設定或大量 PC3 材料。
- 已實連 8506 確認三層說明、命中位置及最小補件卡。程式版本保護觸發後已重啟服務；本輪未驗原生上傳。細節見 docs/releases/2026-09-26-BusyBox跨案例查核.md。
- fetch 後 main 無未納入提交；上一輪 CI 36209995799／36210191752 成功。本輪只推個人分支，Harvey 決定合併。跨案例品質、可信建置、更多 ROM 與公司內網部署仍未完成。

## 2026-09-26 工作區備份還原

- 3cb6e47：本機 create／verify／restore 維運指令，允許資料目錄、逐檔 SHA256、分段搬移、變動檢查與新資料夾還原。設定／key／暫存不纳入，案件材料完整保存且未加密；未完成請求 lock 保留，不自動重跑工作。
- 12 新增測試通過（2.01 秒）；完整 596 passed、23 subtests passed（287.11 秒）。實際從已存 TEST_ONLY 真實 AI 案例建立獨立 7 檔備份，還原工程／AI 收據一致、原碼讀取成功。
- 已實連臨時 8507 還原工作區，確認 AI f8efe6fa 的 PC2 與補件卡；沒有再呼叫 API。臨時服務已關閉、返回 8506，原工作區未替換。
- 操作說明 docs/operations/工作區備份與還原.md；驗收 docs/releases/2026-09-26-工作區備份還原.md。CI 36209995799 尚在執行，上輪 36209543897 成功。公司加密／異地／保留政策、登入部署與跨案例 AI 品質仍待完成。

## 2026-09-26 ELF 動態符號查核

- 3e4ac49：有界 section-backed dynamic symbols，保留 imports／definitions、type／binding 與讀取／截短狀態；不等於呼叫路徑，缺少符號不作排除。3378e2d：中文符號明細與限制面板。
- 九項新增測試，聚焦 31 passed；完整 584 passed、23 subtests passed（333.76 秒）。可攜工程 12／6／5 全通過（187.52 秒）。
- 同 TEST_ONLY ROM／SDK 材料 LIVE f8efe6fa-b169-42d9-a1d0-dadbbde931ca：Sol/high，6 calls、122.36 秒、125749 tokens。AI 利用 curl_version import 與原碼，仍只要求一份建置連結紀錄；PLAN 引文與 COMPLETE 收尾各拒絕一次後修正，不宣稱零錯誤或可直接排除。
- 實際 8506 核對符號面板、AI 解釋與單項補件；原 run bytes 不變。D/R 與界線見 docs/releases/2026-09-26-ELF動態符號查核.md。
- CI 36209233899 工程／ROM job 成功，test 尚在執行；上輪 CI 36208972794 成功。更多 ROM 格式、可信建置、內網部署與跨案例品質仍未完成，只推個人分支。

## 2026-09-26 ROM 成品與 SDK 內容對應

- a4880bd：raw SquashFS 在隔離環境內探查最多六個候選 ELF，每份 4 MiB、共用原期限；相同 bytes 與 SDK 交付檔案對照。2de567e：中文擷取範圍與對應檔案面板。收據 1.1 保留 1.0 相容，不認證同建置或改正式判定。
- 新增 11 項測試；聚焦 37 passed，完整回歸 575 passed、23 subtests passed（287.09 秒）。主機 symlink 與過量二進位拒絕、實際 ROM／SDK 相同內容通過。
- 新編譯 TEST_ONLY ROM／SDK／兩行原碼，LIVE 9d77b448-8117-49b9-bbe7-1c22aaebaf19：Sol/high，6 calls、104.57 秒、115475 tokens；一筆引文錯誤修正後完成 NEEDS_USER_INPUT，只索取一份原碼到成品建置紀錄，明確引用 ROM／SDK bytes 相同，未索取重複 ELF 或大量 PC3。
- 實際 8506 核對擷取一份 ELF、AI 紀錄與單項補件卡；對應表格 AppTest 通過。詳細範圍／D/R 見 docs/releases/2026-09-26-ROM成品與SDK內容對應.md。
- CI 36208741897 尚在執行，上輪 36208351154 成功。重新 fetch main 無未納入提交；只推個人分支。更多 ROM 格式、可信建置、內網部署與跨案例品質仍待補強。

## 2026-09-26 SDK 靜態函式庫分段讀取

- ee2a919：archive_members 改為每次最多 1 MiB 分段 hash，GNU／BSD 長名稱有界驗證，拒絕截斷、錯誤 padding、重複與超限；不追蹤 thin archive。建置證據介面與 PC 判定不變。
- 15 新增案例；聚焦 24 passed，16 MiB 成員解析的 tracemalloc 峰值低於 4 MiB。完整回歸 564 passed、23 subtests passed（331.69 秒）。
- 可攜工程 12 初始／6 補件／5 反向全通過（176.584 秒）；實際 8506 網頁重跑完整 OpenSSL 包，受影響與 PC2 正常。本輪無新增 API 呼叫。
- CI 36208074892 工程驗收／firmware-reader 成功，test 尚在執行。限制見 docs/releases/2026-09-26-SDK靜態函式庫分段讀取.md。下一步回到 ROM 內成品資訊與 SDK 對應；內網登入部署及可信建置驗證仍未完成。

## 2026-09-26 可攜工程驗收

- 4211fa3 修復 scripts/validate_engineering.py：直接使用 Git 內封存檔並查 catalog hash，不再依賴已不存在的本機 datasets。固定要求 12 初始、6 補件、5 反向驗證，全部通過（154.966 秒）。
- 靜態完整必須只缺 runtime_observation；三種運作補件後要求全部條件成立，保留原成品與父材料。沒有更動產品判定或降低 PC3 門檻。
- 新增獨立 CI engineering-acceptance。本機全量 549 passed、23 subtests passed（298.52 秒）；CI 36207664059 還在執行，firmware-reader 已成功。上一輪程式 CI 36207341628 成功。
- 細節見 docs/releases/2026-09-26-可攜工程驗收.md；本輪只驗收與 CI，沒有新增網頁/API 測試。下一步：靜態函式庫串流讀取、ROM 執行檔與可信建置關聯、內網部署。

## 2026-09-26 統一成品 ELF 查核

- 922d605：BuildProof 動態依賴改用有界 Python ELF 解析，與材料盤點共用；保留來源 hash，錯誤不降為空清單。產品路徑不再呼叫 readelf。
- 新增九項測試，聚焦 22 passed；全量 549 passed、23 subtests passed（353.23 秒）。六份 ROM／curl 成品與原 readelf 結果一致；已實際網頁匯入完整 OpenSSL 展示包並重跑，受影響初判正常。
- 舊 engineering 驗收腳本依賴不存在目錄且含過期 PC3 預期；九包直接驗收三項旧預期不符，已查明均缺 runtime_observation，不改判定去迎合舊答案。詳見 docs/releases/2026-09-26-統一成品ELF查核.md。
- CI 36207341628 尚在執行，上一輪 CI 36206896593 成功。後續需修復過期驗收入口、archive 讀取界線、ROM 執行檔與可信來源關聯；公司登入部署仍待辦。

## 2026-09-26 建置聲明與實際補件核對

- 08fa9cb：純 JSON in-toto／SLSA 聲明的 SHA256 與交付檔案核對，保留同名衝突與能力限制；不做簽章／builder 認證，不提升正式判定。649cfb7：網頁中文核對結果與實際檔案路徑。
- 新增事後未簽章 TEST_ONLY 聲明，實際 Runner 補件並延續 AI；原 run bytes 不變。LIVE d1b1442e-4d31-4e11-a6ea-18965c826426，Sol/high，67.06 秒、5 calls、100749 tokens，五步成功，仍只要求一份關鍵原始建置紀錄。
- 已實連 8506 核對材料面板、中文限制及最小補件卡；未測原生選檔 HTTP 上傳。核心全量 540 passed、23 subtests passed（279.10 秒）；CI 36206224304 成功。中文呈現調整後全量同為 540 passed、23 subtests passed（260.98 秒）；CI 36206745055 尚在執行。
- 詳細範圍、D/R 與限制見 docs/releases/2026-09-26-建置聲明與補件核對.md。下一步仍需可信同建置、ROM 執行檔、公司內網登入及跨案例品質驗收；只推個人分支。

## 2026-09-26 引用修正與輸入精簡

- ddbdd48：引用錯誤指出條件／來源並附同來源有限原文提示，不自動接受、替換或認證語意。606aa79：PLAN／REVIEW 模型回覆改為短確認，完整條件與實際回覆仍各自保存。
- 同材料 LIVE 8f8135bc-a654-4861-aa1c-150de0ece81c：Sol/high，5 calls、70.85 秒、81448 tokens，五步全通過，單項補件卡。對照前次 8 calls／117.73 秒／170625 tokens 僅為單次觀察，不保證固定比例。已實連 8506 確認最新卡與用量。
- 全量 530 passed、23 subtests passed（273.33 秒）；程式 CI 36205478451 仍在執行。詳細限制／D/R 見 docs/releases/2026-09-26-引用修正與調查輸入精簡.md。
- 持續待辦：真實補件與原碼成品關聯核對、SDK／ROM 同建置、更多格式、公司登入部署、跨案例人工品質驗收。

## 2026-09-26 最小補件與收尾一致性

- f19d748：使用者材料缺口且無排除／衝突／工具限制時，COMPLETE 不能只用文字索取；要求經既有檢查的 ASK_USER 卡。保留交工程覆核路徑。
- 第三次同 ELF 真實 API：db215ee0-652c-4fec-bdb8-30b42d72ec49，Sol/high，8 calls、117.73 秒、170625 tokens，NEEDS_USER_INPUT，一項既有建置紀錄；實際 8506 已看到最小補件卡與取得方式。原工程 bytes 不變。
- 仍有三次 TOOL_ERROR 後修正成功；不宣稱高效率或已完成補件驗證。下一步改善公告逐字引文與精確搜尋詞、重複輸入。
- 本機全量 527 passed、23 subtests passed（291.70 秒）；程式 CI 36204923946 尚在執行。細節見 docs/releases/2026-09-26-最小補件收尾一致性.md。

## 2026-09-26 ELF 真實模型／狀態範圍

- 兩次 OpenAI API Sol/high 真實調查，每次 6 calls：首次 97.75 秒、第二次 84.21 秒；同 TEST_ONLY source/ELF，工程 run 63976040-37e0-4080-be9c-fc0c7a7a64d6。最新 AI 2b8323e0-6f85-424c-9d24-95f3407180fa 已在實際網頁開啟。
- 修正原碼排除線索與目標成品範圍混淆，ASK_USER 拒絕回覆條件狀態；保存 ELF metadata。第二次仍有一筆 PLAN 引用修正，最後 COMPLETE 而非成功結構化補件，不宣稱完整品質通過。
- 246dd36 修 CI 程序退出探針競態；501581b 狀態／metadata；37ad6f5 處理無 PLAN 邊界。最終全量 522 passed、23 subtests passed（281.06 秒），CI 36204344253 全部成功。
- 後續優先：最小下一步與結構化補件一致性、減少重複輸入 tokens、source-to-binary／實際庫解析。完整限制與 D/R 見 docs/releases/2026-09-26-ELF真實AI查核.md。

## 2026-09-26 ELF 結構與 PC2 線索

- 9df8ebd：新寫有界 ELF32/64 大小端解析，保留 source ID/hash、架構、動態依賴與未驗證狀態；接入候選、AI 初始材料與網頁 PC2 面板。不執行產品，不直接改 CVE 判定；既有 BuildProof readelf 未替換。
- 新編譯 TEST_ONLY ELF 比對 readelf，相同依賴；實際 run 415803a0-88aa-49a4-9d73-8b4725320a10 已在 8506 開啟。新模型 LIVE 尚未執行。
- 全量 518 passed、23 subtests passed（265.16 秒）；13 新增案例。上一輪 CI 36197953797 成功。詳見 docs/releases/2026-09-26-ELF結構查核.md，含讀取界線與 D/R。
- ROM 內任意執行檔、符號／路徑分析、同 build、真實模型語意品質与內網正式部署仍待補齊。

## 2026-09-26 團隊登入邊界

- 程式 7ee3eea：集中驗證既有 Google 部署設定，帳號切換清除 session 暫存，帳號目錄拒絕 symlink；保留白名單與 subject 雜湊儲存方式。
- AppTest 覆蓋未設定、未登入、未受邀、受邀入口；實際瀏覽器驗證臨時 localhost:8507 未設定時不載入工作台，已停止臨時服務並回到 8506。未測公司 OIDC／HTTPS，未公開入口。
- 完整回歸 505 passed、23 subtests passed（250.59 秒）；上一輪 CI 36197384239 成功。詳見 docs/releases/2026-09-26-團隊登入邊界.md。
- 尚待公司登入部署、認證覆核與分享／備份政策，不宣稱完成內網上線；PC 判定及模型調查未改。

## 2026-09-26 收件錯誤指引

- 部分材料與補件新增可辨識的中文容量／封存檔／連結錯誤，損壞 ZIP 不再直接使頁面例外。僅顯示固定訊息，不回顯任意檔名或伺服器錯誤。base 合併先查容量再複製。
- 程式提交 23757a4；嚴格原生 ROM 全量 490 passed、23 subtests passed（295.33 秒）。實際 8506 瀏覽器入口正常；錯誤提交由 AppTest 驗證，未新增原生選檔 HTTP 驗收或模型 LIVE。
- 詳見 docs/releases/2026-09-26-收件錯誤指引.md。未改正式判定／AI／登入政策；只推個人分支。內網認證、完整 ROM／SDK 同建置解析等仍待完成。

## 2026-09-26 大型材料與 CI 環境差異

- 新增大型 ROM／SDK 單檔入口及補件：256 MiB 單檔、384 MiB／5000 檔快照；一般材料維持原限制。後端以 1 MiB 分塊暫存，不用 getvalue 複製整份上傳。Streamlit 仍會暫存上傳內容，不宣稱端到端 HTTP 串流。
- 封裝改為穩定 bytes、0600 權限，重送同一請求可辨識相同材料；補件檢查合併後總容量並保留原 run。Runner.supplement_partial 新增 large 關鍵字選項，預設不變。
- 上輪 CI 真實失敗已追到 bwrap 隔離網路建立被拒絕；新增 ISOLATION_UNAVAILABLE，不再混為缺材料。保留原 CI，另設必須真的讀出 ROM 的工作，沒有停用隔離或變更主機安全政策。舊版工具 -version 回傳碼造成預檢誤報也已修正；詳見 release。
- 本機嚴格要求原生讀取的全量：483 passed、23 subtests passed（285.23 秒）。新建 24 MiB SquashFS 走串流收件及網頁結果通過，原生選檔器上傳尚未列驗收；本輪無新模型 LIVE。
- D01/D02/D05–09；R01/R03/R05/R06/R07/R09/R11/R12。文件 docs/releases/2026-09-26-大型材料收件與環境差異.md。後續仍有 SDK／ROM 同建置核對、更多 ROM 格式、公司登入／案件權限與運維；只推個人分支。

## 2026-09-26 ROM 固定資訊隔離讀取

- 新寫原始 SquashFS ROM 固定三路徑讀取，保存原 ROM／工具／擷取文字 hash 與逐檔狀態；接既有套件辨識、Q1、AI 原文及網頁。副檔名不作格式或判定依據，未知格式保留原檔與能力缺口。
- Linux 必須具備 unsquashfs 與 bubblewrap，CI 加入 bubblewrap；固定命令、唯讀映像／程式／函式庫、独立 namespaces、乾淨環境及資源界線。沒有非隔離 fallback，沒有 mount 或執行韌體。
- 新建 TEST_ONLY 真實 SquashFS 驗證、主機 symlink／過量讀取拒絕、receipt 型別／hash 檢查。輔助隔離探針確認工作目錄不可見、主機網路不可達、映像不可寫、無 API key。瀏覽器核對 run 00d686a0-bc6c-4684-a78f-9589ce448490 的狀態與候選；本輪無新 API 呼叫。
- 最終全量 474 passed、23 subtests passed（252.86 秒），12 項新增測試。D01/D02/D03/D05–09；R01/R03/R05/R06/R07/R09/R10/R12。詳見 docs/releases/2026-09-26-ROM固定資訊隔離讀取.md。
- 仍未完成：大型 ROM 串流收件、廠商容器／分割區／其他檔案系統、完整 binary 解析及 SDK 同建置對應；亦非整套網站安全稽核。重新 fetch 後 main 仍 b95f96d，僅推個人分支，Harvey 決定合併。

## 2026-09-26 網通套件清單與 AI 接線

- 新寫 opkg list-installed／installed control stanza 解析，保留 vendor 版本、原文位置、來源與未驗證身分；不猜生態系統，不直接產生受影響結論。
- 元件清單接入候選、Q1、材料確認表格及 AI 初始原文。自訂名稱 JSON SBOM 也可參與 AI 初始身分材料選擇；維持既有讀取界線。新增 discovery.components 為材料聲明，非驗證事實。
- 真實 API Sol/high：CVE-2023-38546＋TEST_ONLY 清單，110.313 秒、6 calls、NEEDS_USER_INPUT，0 拒絕；讀取 vendor2 原文，補件集中 C1 三項。實際網頁已載入該結果。非真實設備判定，非人工品質通過。
- 最終全量 462 passed、23 subtests passed（395.26 秒），八項新增測試含網頁表格。D01/D02/D03/D06–09、R01/R03/R05/R06/R10/R12；細節與識別碼見 docs/releases/2026-09-26-網通套件清單.md。
- 待辦保留：通用 ROM 解包、SDK／ROM 同建置對應、正式新 CVE 規則及內網運維。找到既有 team_app.py Google allowlist／帳號儲存隔離可沿用，未改服務開放範圍，登入方式與公司設定仍待確認。

## 2026-09-26 公司使用／網頁逐條覆核

- 第一批實務範圍確認為網通設備 ROM、SDK、SBOM、套件清單與原碼，目標公司內網；舊 Demo 僅參考概念。登入方式仍待確認，本機服務尚未開放內網。
- 報告頁新增逐條覆核、重查原工程包與原文、獨立保存及選擇附加。覆核者目前自行填寫，未認證；不改正式判定。共用 Runner 新增 review_conditions／condition_reviews，未修改原 RunEnvelope。
- 完整測試 454 passed、23 subtests passed（368.83 秒）。實際瀏覽器保存與報告選擇通過；驗收紀錄明示非工程人員核准，六條皆未知。無新增模型 LIVE。
- D01/D02/D06–09；R01/R03/R05/R06/R11/R12。詳見 docs/releases/2026-09-26-網頁逐條覆核.md；內網身分與案件隔離、一般網通解析、新 CVE 規則及雙來源品質驗收仍待完成。

更新：2026-09-12 16:16（Asia/Taipei）。Horace 只維護本檔，Frankie 維護自己的同步檔；詳細測試歷史放交件報告，不在此重貼完整對話。

## 正在交付：PC 命中細節與最小補件指引

- 最新使用者要求：PC1／PC2／PC3 要說明實際命中元件、版本、函式／設定及原文位置；補件先顯示最小材料與取得方式，詳細格式展開。
- 獨立分支 `codex/horace-collection-guidance`，基於 PR #23 `0d4f8ee`。沒有改既有判定或 Evidence ID；依條件引用的唯一 E-ID 找到來源、同 context／hash 的原文與行號。UNKNOWN 不改寫成命中；前端及文字報告使用同一組細節。
- 發現 CMake 真實 AI 指引漏列 gzip 樣本：新增 CORE_PARSER_CONTRACT 收件資訊，提供三格式對應材料、角色、用途與格式。新 AI 可參照，ASK_USER 另外附核心清單；清單不當觀測或已驗事實，旧 AI 仍可讀。
- 跨到 Frankie 呈現層的部分限結果卡片／AI 清單及報告，獨立 PR 交審，沒有修改 Runner、contracts、主站或其他人的 checkout。新實包／顯示／scope 測試已驗，完整 suite 與新 Live 接續中。
- 16:24 交件 [PR #26](https://github.com/HarveyLin0110/cvevidence/pull/26)，`4edebaf` 已合入 main `063e581`，解決與 #25 的說明衝突並保留 OpenSSL 情境、動態 Query／公告說明。#22／#23／#24／#25 均已在 main；本 PR 未操作公開站。
- 新 Live 已通過：`84794cc`，Sol／medium、2 calls、24.883 秒，LIST→ASK_USER，16／16。必要材料包含收據、正常日誌與原始 gzip，故障日誌為可選；原工程不變、重開可讀。合入 main 後 19 個核心檔案 hash 與此 Live 一致。34 項呈現／Queries 測試通過；`4edebaf` CI 34683108781 完整 **262 passed＋23 subtests，172.13 秒**、schema 一致。後續文件提交以 PR 最新 checks 為準。
- 收到側邊協調：通用 CVE 調查另由 `codex/general-cve-triage` 負責，本分支沒有重複實作或更動其工作；其完成狀態以該作者交件為準。

## 最新決定：先實作與 Demo，講稿暫緩

- 使用者修正：現場兩版 Demo；第一版資料齊全直接確認有影響，第二版需要補件，只展示 AI 提供「缺什麼、為何需要、如何取得」後結束。**第二版不在現場補件上傳或重新判定**。這取代較早文件要求現場完整補件閉環的展示安排；後端補件能力仍保留驗收。
- 新輸入位於 `demo-inputs/two-flows/`，兩個獨立初始包使用今日同一個 CMake 成品。第一版已在包內備妥運作資料；第二版只有 PC2。catalog 可直接由現有網頁樣品索引讀取，沒有另建 API 或重写前端。
- 交件 **PR #23**：`codex/horace-v2-acceptance` 已合入 PR #20 `da0a4c2` 與 PR #22 `1ca3834`，固定組合 `46b8904`。兩包真 Runner 已分別得到 Affected／Needs Investigation；第二版 Live 為 Sol／medium，4 calls、32.968 秒 → NEEDS_USER_INPUT；沒有補件或重判。兩版實際 Runner 16／16、實際保存結果 UI 呈現 7／7、完整 pytest 239 passed＋23 subtests（300.40 秒），schema 一致。這是本機固定組合驗收，網站仍需整合發布。
- 前一個固定預覽核心 `3ddb6dc`＋Runner `30719a3` 的三格式／歷史驗收為 43／43；新版修補後在 `46b8904` 再跑 43／43 亦通過；已合入 `c6bdf9f` 的最新 UI／導航，核心 bytes 不變，整合後完整測試 **244 passed＋23 subtests，178.07 秒**，schema 一致；實際保存結果再次通過 UI 呈現 7／7。`dff052f` CI 34681852725 成功。公開站由整合端合入 #22／#23 後發布，沒有自行操作服務。第一版基線完整測試為 197 passed、23 subtests，165.34 秒；不當成第二版測試數。

## 可立即接線的版本

- 核心 `7b24110` 已隨整合 PR #17 進 main `256fe2c`；固定整合基線 `c65e9c7` 的 `src/cvevidence_core` 與 Horace 當時核心相同。原 PR #9 最新 `d3211da` 另含 ROM 網站驗收文件，合併狀態以 GitHub 為準。
- **網站 API 已真正接通**：15:16，HTTPS 團隊站頁面版本 `5918858`，工程 run `0a700c0f-0a94-481d-b7b9-23e3aecf6ec4` 追加 AI ID `b4565c59-ee92-492b-93ea-1a22b36e65c3`，`gpt-5.6-sol` 真實 5 calls，LIVE／NEEDS_USER_INPUT。AI 區分截短檔案線索與 CVE 適用性，要求同 build source／libz.a／link 及客戶檔案雜湊。之前 ea5e571 的未接線狀態是歷史，不再代表現站。
- 本機 key 不隨 Git 傳送；網站由服務主機的可信設定取得金鑰。本輪只從網站觸發既有 AI worker，沒有複製金鑰或修改部署。
- **修正提案 `codex/horace-integration-history`**：真 Runner 重現「NOTE 指出未交付入口→工程 DELTA→前文消失」；現在沿同 scope parent 鏈傳回原文字／M-ID／來源 context，再由核心重核；歷史頁也恢復原現象。涉及 Frankie 接線，獨立分支交審，未自行部署。詳見 `docs/releases/Runner_補件歷史接線修正_2026-09-12.md`。
- Git 的 `demo-inputs/` 已在 main：9 初始包＋3 同 build 補件，12 包 hash 通過，約 95 MB。主展示原版為 ROM 03→supplement_03；PC3 新展示另由側邊協調工作建立，不混為已驗收。
- 已收到側邊分工：PC1–PC3 是查核面向，PC3 的實際部署／運作證據允許缺件，由 AI 依缺口新增 Query／補件要求，驗證後重判並保留歷史。側邊在 `var/worktrees/pc3-query-evolution` 實作核心與今日新 Demo；本分支避開其核心改動，維持歷史接線與真實網站驗收。

## 責任與固定限制

| Horace | Frankie／整合端 |
|---|---|
| 新 builder、真實正常觀測、9＋3 輸入包 | 正式收件與工作台 |
| parser、五 query、原文工具、Verifier | Runner、進度、錯誤映射、共用 contracts |
| 三 CVE profile、規則、Claim、缺口與中文摘要 | 結果呈現、報告／下載 |
| OpenAI 動態調查、引用重核與補件內容 | Live／Offline／Replay 入口、可信設定、整次程序期限 |
| 同 build 材料驗證、文字語意及重判 | 不可變 snapshot、parent run、保存與前後比較 |

今日團隊程式、builder、測試與資料全部重新製作。舊 DOCX／Demo 只看概念；公開 OSS 今日從官方重新取得並保留 hash／授權。唯一根目錄是 Fresh，棄用目錄已移至垃圾桶。給隊友的文件使用繁體中文。

分析只讀當次交付，不執行匯入 binary，不讀 factory、測試答案、其他包或未提交補件。人工／AI 文字不直接改已驗條件；初判限定目前成品／profile，保留人工覆核。內部 hash 一致不是供應商認證或實際部署暴露證明。

使用者選 `gpt-5.6-sol`／`medium`，真實 API 已成功。key 由可信程序讀環境或忽略的 `.env.local`，不進 Git。OFFLINE、LIVE、REPLAY、SIMULATED 分開標示。

## 核心與前端接線

1. 工程：`frankie_adapter.analyze_archive_for_runner(archive_path, options, expected_archive_sha256=..., expected_context_hash=..., ...)`；既有 worker 已解包時用 `workflow.analyze_package(context, mode="OFFLINE", ...)`。原 collect/read v0.2 保持相容。
2. 工程先保存，再用 **`workflow.investigate_after_engineering(context, saved_engineering_result, ...)`** 啟動 Live。AI 失敗保留原工程 dict；呼叫端不必重貼已保存文字，核心會從 assessment 取出歷史聲明供 AI 閱讀。仍可用 user_context 傳當次新問題。
3. AI 新原文只先成為 exact-bytes 來源觀測，再 collect→verify→assess。自由推論不升格成條件；未完成調查不偽裝重判成功。
4. 延後 AI 回傳是 stage wrapper，不能取代完整工程 JSON。依 context／CVE／內外 engineering_assessment_id 核對後組合顯示，保留工程及 AI 各自不可變紀錄；禁止補造 ID 通過 guard。
5. `analyses[].condition_groups` 提供共用前提與 PC1／PC2／PC3，僅供呈現，不改 assessment hash、Evidence ID 或判定。條件維持 SUPPORTED／BLOCKED／UNKNOWN，不轉成舊 TRUE／FALSE。
6. 新 Live 有 started_at／finished_at；Replay 有原時間、本次播放時間及 original_record_hash。舊紀錄若未存原時間，顯示未知，不以播放時間代替。
7. 原文鏈在 **`evidence[].excerpts`**：X-ID、source/file hash、行號與 text 已提供。現有 renderer/report 主要顯示 witnesses，請補呈現 excerpts 與同 scope 來源操作。分析與原文工具須使用同一核心版本，避免舊 X-ID 演算法混用。
8. 未支援 CVE 的 assessment/ai=null；即使外層程序 COMPLETED，也不能顯示安全。malformed tar 可拋 TarError，worker 需保留例外→失敗映射；收件前失敗未必有 stage event。

兩入口為「描述現象」與「指定最多五個 CVE」，候選、產品適用性、異常原因分開。五 query 為 Q1_COMPONENT／Q2_BUILD／Q3_IMPLEMENTATION／Q4_BINDING／Q5_PATH；AI 新問題不固定為 Q6。

03 來自 ROM 02、06 來自 CMake 04、09 來自 curl 07。同 build 補件不更換 binary，建立新 context；不同 build 不合入原案件。中性文字存 statement_context，不阻擋判定；未決／矛盾／新增範圍聲明才阻擋。後續足夠證據可解除歷史待查，原 M-ID／source context 保留。

## 最新驗收與限制

- 本次歷史接線分支以整合基線 c65e9c7 執行 **193 passed、23 subtests，170.96 秒**；契約重產一致。包含真 CMake NOTE→DELTA、ROM 聲明重新核對、不可變歷史、scope／損壞拒收與歷史頁情境回填。網站 Live／CMake 補件紀錄見 `docs/releases/團隊站_CMake_Live_實測_2026-09-12.md`。

- 合回 main 的 `e887c00`：**165 passed、23 subtests，52.77 秒**；schema 重產一致。之後 `7b24110` 只補 AI 的保存文字上下文及專項驗收，50 項 AI／回流聚焦測試通過；7b24110 的 CI 34678280555 已通過：167 passed、23 subtests，45.22 秒（含當時 main 的合併檢查）；後續 head 以新 checks 為準。
- 九格工程 9/9、三組補件 3/3；C 另從 Git archives 獨立驗 9＋3 與九項邊界。三個展示輸入各十次共 30 次 OFFLINE，結果／ID 穩定。這些是具名既有驗收，不冒稱每個新 head 都重跑全部。
- A 中性／矛盾語意已整合。C 第二輪 ROM 文字、補件、重核與失敗隔離 **16/16**，原檔／結果保留，沒有新核心 blocker。
- B 第二輪 2 個模擬失敗保留通過；原兩筆 Live 一通過、一筆 8 calls 耗盡。主線 `dd47a1e` 修工具參數引導及剩餘預算提示後，同一原問題 **5 calls／44.872 秒完成**，8 筆新原文重核，仍 Not Affected。原失敗完整保留，不提高預算或放寬引用核對。
- `7479368` 新增未交付網路 gzip 入口：**4 calls／36.449 秒** → ASK_USER、工程待查，既有條件不變，Live／Replay 時間通過。必要補件與可選動態測試分開，漏洞重現不是必要交付。
- **`7b24110` 延後 AI，呼叫端 user_context 留空**：AI 自動讀保存的另一入口聲明，**4 calls／31.198 秒**提出兩項同 release／build 的最小材料；工程與歷史保留、重判仍待查、Replay 原時間與 PC 分組核對通過。證據在 `docs/releases/驗收證據/延後AI保留歷史聲明Live摘要.json`。
- 四個原始 Live 情境、注入／錯引用、真包 source 篡改／多 ELF／build 衝突另見完整交件及驗收證據。精確引用不等於語意證明；沒有宣稱全面防注入、所有 CVE 自動判定或部署安全。
- `9f3ac28` 已 pip 打包安裝，repo 外 site-packages 可載入 reviewed_sources.json 與 PC 分組。之後 7b24110 再次打包，repo 外 CLI 跑真 CMake 05：五 query／Not Affected，安裝 ai.py 與工作樹 bytes 相同，不新增依賴。

## 已接收的並行交件

| 工作 | 固定測試核心／結果 | Git 交付 |
|---|---|---|
| A 語意 | 真包文字／矛盾／同 build 重核已通過 | 已合入主線，原分支 codex/parallel-semantics |
| B 第二輪 Live | 44efc7b；含成功、耗盡及模擬失敗，未掩蓋失敗 | 主線 848cb32／c1d0604／7853ed3；Parallel_AI_R2 報告 |
| C 第二輪回歸 | 44efc7b；16 PASS／0 FAIL | 主線 19a8b78／65789d2；Parallel_QA 報告 |
| D 指定 consumer | 44efc7b；基本 JSON／隔離通過，兩個原文呈現失敗 | 分支 codex/parallel-contract-qa，754e6a3；未混入最新產品通過數 |

D 的 integration a47a1a3 未接分析屬當時結果，main 新 OFFLINE 已取代該狀態；c65e9c7 已接 PC／excerpts 與 Live worker，網站具名验收見上方。A/B/C/D 第一、二輪均已交件，不作為仍活躍名額。新的網站 Live 及歷史接線狀態以本檔最上方為準；舊 consumer 結果不替代新版本驗收。

本環境無跨對話讀／發訊工具，透過 worktree MD、Git commit 與 PR 收件，不宣稱已自動傳訊。使用者授權最多主線之外三個活躍工作，依需要續派；側邊協調者管理任務。heartbeat cvevidence 每五分鐘補巡檢，17:35 截止，完成／叫停後停用。

## 存放

輸入 `demo-inputs/`；程式 `src/cvevidence_core/`；builder `tools/demo-data/`；可公開驗收 `docs/releases/`；完整 build/artifact/run/report 留忽略的 var 下。只 stage 本人改動，不強推，不把新原始客戶資料／key 上 Git。由整合負責人審查確切 head 後合 main。

逐項責任與剩餘聯合驗收見 `docs/releases/Horace_責任驗收與剩餘接線.md`。

## 2026-09-26 賽後 P0（開發分支，待 Harvey 決定合併）

- 第一項：通用 LIVE 調查加入受控官方公告／上游 patch 取得，保存 URL、取得時間、原始與文字 hash、截斷與失敗；P-ID 不作產品工程證據。來源政策未支援／連線失敗屬工具缺口，不自動要求使用者補件。
- R02／R03／R09／R10／R12：CNA 參考與官方頁面連結仍為不可信資料；限制 HTTPS 來源、DNS 公網位址並綁定連線、拒絕 redirect／query、限制大小與期限。新增來源須經操作者修改政策。
- 單元驗收：來源政策、私有 DNS 拒絕、修補連結與 hash、抓取失敗分類。完整 LIVE 驗收待全部 P0 接線後記錄。
- 第二項：新增 PLAN／REVIEW 工具階段。新 CVE（已公開公告）須先建立 3–8 個有公告逐字引用的專屬條件，涵蓋 PC1/2/3，再讀產品原文並逐項 REVIEW。必要／排除條件與查法在 REVIEW 不得被改寫；支持／反證／衝突必須有產品 X-ID。R04／R05／R06：這是可覆核調查計畫，不新增正式驗證規則，不讓 AI 改 assessment。
- 第三項：網頁／文字報告以條件呈現「尚未查閱、原文支持／排除線索、矛盾、工具能力、使用者材料缺口」，原五類材料索引折疊並明示不是補件要求。通用 ASK_USER 必須已有 REVIEW 的 USER_MATERIAL_MISSING；公告取得失败與缺驗證器不冒充使用者缺件。R05／R07／R12；AppTest 驗證分類、說明與 scope 拒絕。
- 第四項：ASK_USER 加入結構化 requests，最多三項且只能指向同一條件；必填向誰取得、方式、用途、現有材料不足原因與取得後能確認什麼，可附擇一替代方式。新 CVE 禁止純檔名清單；已有排除線索且無矛盾時先收尾交覆核，不再索取其他條件材料。舊專用流程相容文字要求但同樣限制三項且去重拒絕。網頁先顯示最小材料與取得方式，細節折疊。R04／R05／R12；驗收含過量、重複、跨條件、工具缺口與無取得方式拒絕。
- 第五項：通用調查先讀本次 SBOM／build record 的受限原文，並按公告／patch 的檔名重排來源索引。結構化補件前以完整檔案索引比對所需路徑；命中但未读、虛構已讀來源、已存在卻未說明不足，都拒絕並回傳下一步 READ 位置。這是路徑／原文已讀檢查，不冒稱語意充分性已驗證。R01／R04／R05；40 項聚焦測試通過（含前四項與 provider 相容）。
- 真實 API 第一輪（Sol/high）：CVE-2022-35252＋完整 curl 材料完成，134.854 秒，找到 cookie.c 控制碼拒絕線索，沒有補件；CVE-2023-38546＋同一真實 binary/SBOM 的部分交付完成，125.546 秒，只要求一份 target/link manifest，給取得方式與替代材料。兩筆原工程結果不變；第一轮有引用／範圍修正，不掩蓋重試。
- 實測修正：部分 CNA 缺少原廠連結，加入 curl 公告的受控 CVE URL 模板；強調 P-ID 不混入產品引用、通用模式的已讀原文不稱核心已驗工程事實。報告帶出結構化補件細節。聚焦回歸 132 passed／12 subtests；更新兩個舊測試，不再把缺條件計畫的直接 ASK_USER 視為成功。
- 最後來源修正後的完整材料 LIVE 取得 curl 原廠公告與 patch，完成 REVIEW，但總結前超時；保留 TIMED_OUT，不列成功。新通用流程新增取公告／PLAN／REVIEW，故獨立調整通用 PC 調查為核心 240 秒、網頁整次 300 秒；原三專用 profile 仍 145／180 秒，12 次工具上限與引用驗證不變。R09：單一共享期限，不在重試重置。網頁也折疊去重原工程缺口，避免重複顯示五次像補件要求。

- P0 最終程式 `3b837e7`：完整材料 CVE-2022-35252 實連成功（整次約 160 秒、8 calls、無工具／引用錯誤），讀取官方公告／patch、版本、cookie.c 與建置線索後提出排除觀察，沒有補件。
- 最後從本機網頁啟動 CVE-2023-38546 部分材料實連：155.595 秒、9 calls、NEEDS_USER_INPUT；只問 C2 同一修補條件的 easy.c／cookie.c／cookie.h，含取得方式與替代方案，C3 工具能力不足另列。期間錯誤提案有被 guard 拒絕並修正，完整紀錄保留。正式判定仍待工程覆核。
- 自動驗收：完整回歸 409 passed／23 subtests（既有 duplicate ZIP 警告）；後續時間調整相關 82 passed；最後 UI／共享期限專項 9 passed。不混算成最後版本全量重跑。詳細記錄見 `docs/releases/2026-09-26-P0-通用CVE調查.md`。本機網頁維持 8506，改動分開提交至 codex/horace-development，由 Harvey 決定合併。

## 2026-09-26 P1／P2 延續

- P1 搜尋：公告／patch 路徑、函式、設定符號與建置紀錄共同排序，保存掃描上限與原因；排行不是證據，不宣稱掃過所有檔案。R01/R03/R05。
- P1 版本：保留 CNA defaultStatus／changes；數字版本可比對明確區間，發行版／回補／預發行與未覆蓋範圍保持未知；網頁分開公告受影響與未受影響宣告。R05/R06。
- P1 條件呈現／覆核：逐條顯示原文檔名與行號，建立有 hash 的條件證據包；本機操作員可用 scripts/review_conditions.py 提交逐條理由，Verifier 重查原文與 scope，保存獨立覆核收據。人工身分未認證、語意仍屬人工判讀；不能把此收據當成自動安全判定。R01/R05/R06/R11；10 項相關測試通過。
- P1 部分材料：新增 partial 格式與網頁多檔收件，內部產生清單、記錄使用者身分聲明；inventory hash 不冒充產品 binary。即使是既有 CVE 也走通用待查，無完整 build 不套專用安全判定。R01/R06/R07；部分收件及通用回歸通過。
- P1 公開候選：支援 CycloneDX／SPDX 套件身分；網頁明確同意後向固定 OSV API 查詢最多五個元件，症狀只在本機比對排序，不外送原碼／日誌。保存回應 hash、查詢與 scope；未涵蓋與查不到不視為安全。R02/R03/R10。規格來源 https://google.github.io/osv.dev/api/ 。
- P1 接續／P2：使用者明選前次 AI，僅同 run 或明確祖先可讀；重驗 bytes 後才沿用引用，材料缺口重新 REVIEW。背景工作、逐步存檔、取消程序群組、時間／呼叫上限及供應者回報 token 門檻已接線；不宣稱 token 精確硬上限或供應者端零費用取消。R01/R05/R08/R09/R11。38 項 AI 介面、23 項控制／來源／部分材料、10 項工作台測試通過；真實 Django 接續調查正在驗收。
- 真實實連：CVE-2024-42005，官方 Django 4.2 SBOM 初次 112.807 秒／5 calls，只要求一份原始套件；补入官方 wheel 的四份原碼後，接續 101.156 秒／8 calls，完成 5 條條件的覆核觀察、引用 query.py 與 sql/query.py、不重複補件，原紀錄不變。仍未證明已部署產品受影響。
- P2 網頁實測：實際啟動 API、看到 RUNNING 與目前步驟，再按取消；保存 CANCELLED／USER_CANCELLED 與 checkpoint，可下載，沒有改工程結果。
- 真實第二 CVE 觸發 token 門檻並保留 BUDGET_EXHAUSTED。發現公告 patch 的長測試字串與接續重複公告耗用過多，加入傳送原文選段與去重；完整快照仍保存，未傳送部分不作不存在證明。正在從原 checkpoint 驗收。

- 最終 `5e2ba52` 全量：430 passed、23 subtests passed（231.66 秒），只剩既有 duplicate ZIP 測試警告。CVE-2023-36053 去重後接續完成：70.667 秒／4 calls，6 個條件、5 個有原文引用，命中 validators.py；無工具拒絕、無補件。完整失敗與預算停止記錄保留。
- 網頁已重啟至最後版本並留在成功 LIVE 結果；可查三輪預算停止／成功歷史，另有實際取消紀錄。詳細範圍、限制、D/R 規則與驗收見 `docs/releases/2026-09-26-P1-P2-通用調查延續.md`。本輪 12 個 commits 只推 Horace 開發分支，由 Harvey 決定合併。

## 2026-09-26 網頁實測修正

- 真正操作 8506：SBOM 症狀收件→OSV 20 候選→選 CVE→材料盤點→文字補充 child；既有官方 Django wheel 從網頁觸發 token 門檻停止，再接續完成 5 次真實模型回應、具體 PC1/PC2 原文及封裝綁定、PC3 維持未知，未發出補件清單。
- 修好候選 CVE 歷程分支、公告 n/a 誤作精確版本、候選 JSON／長原文呈現、Markdown 檔名標題，以及刷新遺失公開候選。Runner 新增 public_discovery(run_id)；新查詢保存不可覆寫索引及 hash/context 核對，不改 RunEnvelope。D01/D06–09；R01/R05–07/R11–12。
- 更新後網頁確認：CVE 分支開到最新補件、原文能展開、刷新後 20 候選還原且沒有新增連網收據。24be2f7 全量 434 passed、23 subtests passed，257.06 秒。原生檔案選擇器多檔上傳／下載落地未列本輪瀏覽器通過。
- 詳細界線及實測 ID：docs/releases/2026-09-26-網頁實測與修正.md。只推開發分支，由 Harvey 決定是否 merge。

- 2026-09-26 後續網頁驗收：修正直接進報告漏附保存 AI、請求重載回到收件使 AI 停用；AI 結果優先、PC 概況與分段、最小補件提前、首頁兩路徑與材料差異摘要。新草稿先收一份元件清單／SBOM，缺少時先補產品版本，不一次索取全部工程資料。D01/D06–09；R01/R05–07/R11–12，原判定與引用驗證未放寬。
- 實際網頁：双 CVE 請求 5fbc3e6a 各自分析／重載 e0f1a888、383a89bd；草稿 a0688f8b；報告選 d907b658 與排除 AI 都通過；d390efc0 補件先顯示取得方式。最後程式 50b8b24 完整測試 438 passed、23 subtests passed，326.71 秒。新輪未額外呼叫模型，原生上傳／下載落地仍未列瀏覽器通過；詳見網頁實測 release 紀錄。

## 2026-09-26 原始目標與 Harvey 賽後方向審核

- fetch 後 main 仍是 Harvey 合併 PR31 的 b95f96d，已在本分支；provider integration 分支沒有漏合提交。核對 V5、PC 分層後續修订與 AIP spec，保留 API／CLI 共用工具、來源／模型收據、版本綁定、明確同意及人工覆核方向。
- 新發現並以失敗測試重現：空／不完整 usage 被當完整；損壞 checkpoint 使 timeout／cancel 無法保存 end。dcce7a0 修用量與共用門檻；bb401cf 保留終止結果並處理網頁進度錯誤；03ec156 讓個人分支 push 也跑既有 CI。
- 完整回歸 450 passed、23 subtests passed（343.72 秒），schema 再產生一致；網頁重啟首頁實連正常。本次無新增模型 LIVE，不能當成雙來源同版品質驗收。D01/D02/D06–09、R05/R07–11。
- 尚待：一般產品解析、新 CVE 正式驗證規則、網頁人工覆核閉環、同版雙來源及多案例品質、人用檔案選擇器／下載验收；詳見 docs/reviews/2026-09-26-產品目標與Harvey變更審核.md。未把人員核准或所有 CVE 自動判定標為完成。只推開發分支，Harvey 決定是否合併。
