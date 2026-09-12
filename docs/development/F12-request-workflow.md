# F12 情境與多 CVE 請求管理交付
日期：2026-09-12。Frankie 功能分支；8506 驗證。沒有修改整合端 core_service/core_worker/catalog，也未變更 RunEnvelope 或判定語意。

## 行為
- 無檔案時可只描述情境／指定 CVE，保存 DRAFT，回傳 Horace 現有 discover_candidates 的收件引導，不建立假分析 run。
- 上傳／選取工程包，可輸入最多5個 CVE。空 CVE 執行元件候選收件；多 CVE 分開保存 run。
- 同一請求凍結 archive SHA256；個別 CVE 的 run ID、CVE scope 獨立。
- 同 UUID＋相同完整 RequestSpec 重試回傳既有結果；同 UUID 不同內容拒絕。
- 並發請求用原子 .lock 阻止重複工作；中途未正常完成會保留 lock，不自動重跑已保存子 run。人工先檢查，再決定另建請求；尚未提供自動續跑與解除鎖工具。
- DRAFT 可透過 parent_request_id 接到帶資料的新請求，原草稿不改寫。
- 切換表單输入會清除上一請求／run 的畫面選擇；歷史仍保留。
- Web／CLI 共用 Runner.submit_request/read_request；UI 有請求歷史、CVE 子紀錄切換與 JSON 下載。
- 整體期限沿用一個 deadline，逐個 CVE 傳剩餘時間；本機 archive 搬運只有大小限制，未宣稱可取消任意 I/O。

## 接口
新增 request_contracts.py（RequestSpec/RequestRun/RequestResult）與 requests.py（RequestStore/parse_cves）。既有 RunEnvelope 不變。
RequestResult 狀態：DRAFT／COLLECTED／PARTIAL／FAILED，僅表示收件執行結果；所有現有 assessment 仍 null。
Result.spec 含 request_id、parent_request_id、symptom、cves、archive_sha256、manifest_sha256；runs 包含每個 cve_id/run_id/status。
JSON schema：contracts/schemas/request-result.json，由 scripts/export_contracts.py 同時產生。

Python：
```python
draft = runner.submit_request(symptom="更新匯入出現 gzip EOF")
result = runner.submit_request(
    path="demo-inputs/cmake/06_cmake.tar.gz",
    cves=["CVE-2022-37434", "CVE-2099-9999"],
    parent_request_id=draft.spec.request_id,
)
saved = runner.read_request(result.spec.request_id)
```

CLI：
```bash
PYTHONPATH=src python -m cvevidence.cli --store var/runtime request --symptom "更新匯入出現 gzip EOF"
PYTHONPATH=src python -m cvevidence.cli --store var/runtime request --package demo-inputs/cmake/06_cmake.tar.gz --cves "CVE-2022-37434,CVE-2099-9999"
PYTHONPATH=src python -m cvevidence.cli --store var/runtime request-show REQUEST_UUID
```
CLI --request-id 可讓同內容重試去重；--parent-request-id 連接草稿；--timeout 為整體期限。

## 驗收
- 63項 pytest 通過；新測試9項，包含真實parser＋合成材料、並發、第二子run前故障／重試、不同payload、deadline、草稿延續和AppTest。
- 真實 Horace 06_cmake.tar.gz：archive SHA256 f49dce2610e68ddff8bf458173bcb15aaa4624d30ce9188f64e6d91feb061d54。
- request 90458055-7530-4e89-a8a3-5cbba16a0e7e：兩個CVEs、兩個獨立run、各260來源、相同archivehash，unknown CVE顯示UNSUPPORTED_CVE，assessment=null。
- 瀏覽器8506：情境填寫→提交→DRAFT與資料需求引導成功；未顯示AI／工程分析已完成。
- 測試命令：PYTHONPATH=src python -m pytest -q；schema再產生後需無差異。

## 整合注意
僅調用 CoreService.retain/retain_stream 和 Runner.start_file 的既有接口。整合端已確認暫不變更這些入口。
service可配置port（e7f00e7）預設8506；整合端合入時請明確傳 --port 8505。
本分支尚未合入整合端的正式catalog選單修正；不可用較舊core_service覆蓋整合版本。
每個請求成功保存後原子發布結果；意外中斷留下lock與已保存run。這是禁止模糊重跑的策略，不是自動恢復／資料庫交易。
後續獨立里程碑：操作事件、請求中斷處置、動態InvestigationTask與條件契約（先對齊Horace），由此功能PR驗收後再做。
