# F15 真實 AI／補件閉環驗收
日期：2026-09-12。程式基線：25a39bf（含 F15 f11ca7a 與 main e9cc996）。本地 WSL，未部署公開站。
資料：Git 已交付 demo-inputs/cmake/06_cmake.tar.gz；CVE-2022-37434。非 TEST_ONLY 模型收據。

## 實際結果
1. 工程 run 9477f079-4a19-4714-b3f3-1cc7c5552c5f：Needs Investigation。
2. AI 63302644-ac91-40c4-b6ba-687251993650，Sol/medium：TIMED_OUT；失敗保留。
3. 同工程 parent 的新 AI b6b6201f-b272-4ff9-8089-ab786837fb67，gpt-5.6-sol/low：NEEDS_USER_INPUT，2次 API call、2個步驟 LIST/ASK_USER。
4. AI 要求同 build 的 build/cmake/zlib/libz.a，理由是查核 library_binding 與 product_binding 的未知部分。引用存在與scope/hash核對通過，不等於語意認證。
5. 真實保存結果經工作台 AppTest 顯示／切到報告，報告包含該 AI ID；載入未呼叫模型。
6. 經實際工作台按鈕套用已交付 CMake 補件、重新 Q1–Q5／規則判定；新 run 46cb52e9-d510-4932-b85f-45d200142ac4：AFFECTED。不是模型改寫 verdict。
7. 原工程與原 AI 紀錄不變。資料與完整模型紀錄留 var/ai-acceptance，不提交Git。

## 可重跑與覆核
已有本機紀錄時：
PYTHONPATH=src python scripts/validate_saved_ai_ui.py --store var/ai-acceptance --ai-id b6b6201f-b272-4ff9-8089-ab786837fb67
可加 --apply-cmake-demo-supplement，會建立新的補件/分析run；只適用交付 CMake06案例，不外送模型。

25a39bf 全套136項pytest通過；10項AI邊界測試包含並發、timeout、權限/環境與AppTest。
瀏覽器8506確認新版產品標題、歷史折疊、初始步驟反灰；真實AI報告/補件閉環以AppTest驗證，不冒稱瀏覽器點擊過整段LIVE。
測得一筆成功不足以宣稱所有CVE/情境可靠、無提示注入、固定延遲或完整安全稽核。
公開8507與新Horace核心由整合端另驗；此報告不替其宣告完成。
