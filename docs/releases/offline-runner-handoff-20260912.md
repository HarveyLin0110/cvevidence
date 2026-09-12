# OFFLINE 工程接線交付
日期：2026-09-12。核心固定 origin/codex/horace-fresh-core 的 0a480df；整合分支 codex/integration-offline。

## 可串接契約
```python
runner = Runner(RunStore(account_scoped_store))
# parent必須是COLLECTED且有context_hash的真實收件run；指定CVE不得改成另一CVE。
child = runner.analyze_offline(parent.run_id, cve_id=None, symptom="", timeout=120)
if child.engineering_payload_sha256:
    payload = runner.read_engineering(child.run_id)
```
- analyze_offline保存新child，parent永不覆寫。CVE可由parent承接；無CVE收件須明確指定一個。已完成的分析run不能再直接當分析父項，應回原收件或先補件。
- 新欄位engineering_payload_sha256指向本帳號store/blobs內容定址JSON；UI不得自行拼blob路徑，必須read_engineering。
- payload保留Horace正式JSON：input/context_hash/archive_sha256/discovery/analyses[]/events。目前analyses恰好一個與child.cve_id一致。
- analyses[0]包含queries/evidence/assessment/ai/summary；條件SUPPORTED/BLOCKED/UNKNOWN不轉成舊TRUE/FALSE。
- RunEnvelope.assessment保持None（舊契約欄位不承載新的工程語意），正式判定讀payload.analyses[0].assessment。不要用舊report()宣稱完整工程分析報告。
- engineering_status為COMPLETED或UNSUPPORTED_CVE；ai_status為OFFLINE或NOT_RUN；未知CVE沒有assessment。
- worker只執行固定OFFLINE。查詢、verify與assess在同一程序完成；保存JSON不是可反序列化重用的VerifiedEvidence憑證。
- 讀取核對blob hash、run/input/CVE/context/archive及父快照；跨帳號RunStore看不到其他帳號run。
- 失敗/逾時保存FAILED/TIMED_OUT子run，沒有部分判定或payload。
- NOTE補件清空原工程結果，重新分析會把未驗證聲明交給規則覆核；DELTA先保存新context再分析，保留原父鍊。
- v0.2 schema新增選用欄位/狀態，舊run仍可讀；舊版程式未必能讀新run，因此部署必須固定相容版本並重啟。

## 已驗收
101 pytest passed。新增7項包含真實CMake包分析、同build補件再分析、父紀錄不變、錯CVE、帳號store隔離、竄改blob拒絕、worker錯scope拒絕、模擬逾時、未知CVE不判定、文字補件覆核。
CMake06為NeedsInvestigation，補件後為Affected；結果由當次核心運算，沒有在adapter用檔名映射。

另外透過真實worker保存三種格式：
| 格式 | package | run | 結果 |
| --- | --- | --- | --- |
| CMake | 06_cmake | c21f3845-063f-4127-aafb-2e89613fde95 | 5 queries / NeedsInvestigation / OFFLINE |
| ROM | 03_rom | 7eca5448-3467-4378-96f1-5c813355e38a | 5 queries / NeedsInvestigation / OFFLINE |
| curl | 09_curl | 679d42b5-4a00-4acd-b15d-b96dedf2a8a1 | 5 queries / NeedsInvestigation / OFFLINE |

本機驗收store：/home/frankie/projects/cvevidence-integration/var/offline-acceptance。
原始payload不提交Git。前端可用同機唯讀驗收store；正式網站仍必須由登入帳號scope建立自己的Runner。

## 限制與下一步
- 未接獨立LIVE AI入口、工作佇列、完整九格Runner驗收與所有程序資源配額；不得宣稱全部完成。
- 既有subprocess期限限制保留；完整程序樹與部署資源隔離仍需專項驗收。
- UI由另一Frankie功能session接：明確執行→選新child→read_engineering→renderer/report。PC分組不能猜。
- 8507仍固定1006bfc測試手冊版本，本次核心不直接部署。
- D01/D05/D07/D09：固定交付、固定worker、可重跑測試、同步正式契約。
- R01/R06/R07/R08/R11：scope、正式驗證與判定、失敗不出結果、OFFLINE、不變父run；不把這些測試擴大宣稱為完整安全稽核。
