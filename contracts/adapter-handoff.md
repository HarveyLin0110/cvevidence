# Horace 核心接線提案
狀態：待雙方確認。此版本先固定 Frankie 的流程保存，可調整以適配 Horace 真實核心。

Operator 設定 CVEVIDENCE_CORE_MODULE 為已審閱 Python 模組；Runner 在獨立 worker 中呼叫：
- collect_for_runner(payload: bytes) -> CollectedPackage 的 dict。
- read_evidence_for_runner(payload: bytes, record: dict) -> bytes（完整證據，最高 1 MiB 預覽傳輸）。
模型定義位於 src/cvevidence/adapters.py。請勿直接把 TEST_ONLY stub 作正式核心。
這些函式是 Frankie Adapter 包裝層，不要求 Horace 改名既有 ingest_package／read_excerpt。
下一個 M5 由包裝層對接 Horace 入口，並擴充分析回應／Query event／驗證事實，不能把 collect 視為整個分析。
Runner 擁有 run_analysis、save_supplement、UUID、快照、保存與 deadline。

尚待對齊：
- 大型 package reference 代替 bytes 傳輸；來源 root、manifest 與材料定位。
- InputPackage 是否可無檔案／無 CVE，以及 discover_candidates 的獨立初始階段。
- 真實 verifier 對 provenance、symlink、跨產物 build、完整性／矛盾的狀態。
- Evidence 的穩定 ID、locator 與原文 range。
- collect_evidence／verify／assess／investigate 階段事件與整次 deadline／取消。
- OFFLINE、LIVE、REPLAY 各自輸出語意；錯誤與 assessment 的相依。
- max3問題只來自先前 UI／AIProposal 草案；如 Horace 動態調查需要更多工作項，另建 InvestigationTask。
- 補件是 delta 還是 replacement snapshot、何時允許真實 build 變化及 REVIEW_REQUIRED。

目前合成 integration tests 驗證引用範圍、保存與錯誤，不验证真實漏洞。
