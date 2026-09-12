# Horace 第一輪資料與核心交件

2026-09-12。這是可供接線的匯入與唯讀核心，以及今日新建資料的第一輪驗收；尚非完整 CVE 判定引擎或 Live AI 交件。

## 已驗證

- 六個新 build 完成：ROM OpenSSL 1.0.1f on/off、CMake zlib 1.2.12/1.2.13、curl 8.3.0 官方產品程式修補前後。
- ROM 有真正 SquashFS 映像、解包 hash、正常 TLS 與設定備份還原。新版 r2 已另外從乾淨來源重建，實際 localhost TCP client/server 正常連線通過，保留 SSL_read 原始位址與載入映射。
- CMake 的 zlib 為靜態連結。合法 gzip 額外標頭正常讀取；截短檔實際返回不完整錯誤，未執行漏洞攻擊。
- curl 正常經本機 SOCKS5 遠端名稱解析下載 HTTP 測試資料，保存實際觀測。此 build 不含 TLS；依賴平台的 libc/zlib。
- 九個初始包與三個補件 archive 均通過解壓/manifest/hash 核對。三組補件同成品合併通過。
- 15 項核心單元測試通過：範圍限制、篡改/缺件區分、無效引用、ZIP 路徑與重複項、不同 build、同 build 不可換 bytes、口述不作已驗事實、無材料不硬猜 CVE、未知版本/CVE。
- 第一份 ROM 的 47 個 libssl archive members 及第一份 CMake 的 15 個 zlib members 已核對編譯紀錄/來源/object/archive；這項內部一致性核對不等於供應商身份認證。

## 資料成績

| Dataset | 初始包資料驗收 | 同 build 補件驗收 | 工程判定 | Live AI |
|---|---|---|---|---|
| fresh-rom-r2 | 3/3 | 1/1；432 → 4294 檔 | 未執行 | 未執行 |
| fresh-cmake-r2 | 3/3 | 1/1；260 → 409 檔 | 未執行 | 未執行 |
| fresh-curl-r1 | 3/3 | 1/1；6245 → 6250 檔 | 未執行 | 未執行 |

完整原始報告：`var/validation/data-acceptance-20260912T043942.json`（首輪三種資料）及 `var/validation/data-acceptance-20260912T045055.json`（新版 ROM r2；15.528 秒）。當次資料驗收耗時 89.602 秒，包含 12 個 archive 解壓及驗證；不是單次產品查核耗時。Git 只保留此摘要與 catalog，完整工程包不進 Git。

`fresh-cmake-r1` 是較早未附 SBOM 的封裝，請用 r2。ROM 請用已另驗的 r2；既有 r1 保留為歷史資料。選定六個產品 build，另有兩個早期 ROM build/失敗嘗試保留於 build 紀錄，不混算成九格工程通過數。

## Frankie 可先接的介面

```python
from cvevidence_core.integrity import ingest_package, safe_extract
from cvevidence_core.sources import list_sources, search_sources, read_excerpt, compare_sources
from cvevidence_core.supplements import validate_supplement, interpret_statement
from cvevidence_core.catalog import discover_candidates
```

`InputPackage` 內含當次唯讀來源範圍。`public()` 回可 JSON 化的欄位；請勿將本機 root path 當前端接口。補件驗證回新增檔案與同 build 狀態，Runner 再建立不可變快照；此函式不寫 Frankie 的保存區。

- `ingest_package(path, expected_manifest_hash=None)`：完整性不符拋 `IntegrityError`；格式不支援拋 `UnsupportedError`，均無正式判定。
- `read_excerpt(context, source_id, start_line, end_line)`：回原文、行號、來源 hash、excerpt ID/context hash；不可用任意檔案路徑代替 source ID。
- `validate_supplement(context, path)`：同 build 回 `READY_FOR_NEW_SNAPSHOT`；不同 build 回 `DIFFERENT_BUILD`；原檔替換矛盾拋錯。
- `discover_candidates(context=None, symptom='', requested_cves=None)`：候選只帶公告與元件匹配依據；不產生 assessment。三個深查 profile 暫標 `IN_DEVELOPMENT`。

範例是目前 Horace 介面提案；Frankie 共用 contracts 尚待回覆對齊。

## 在 Fresh 根目錄執行

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m cvevidence_core inspect var/artifacts/datasets/fresh-rom-r2/packages/03_rom
PYTHONPATH=src python3 -m cvevidence_core sources var/artifacts/datasets/fresh-rom-r2/packages/03_rom --contains sdk
PYTHONPATH=src python3 -m cvevidence_core validate-supplement var/artifacts/datasets/fresh-rom-r2/packages/03_rom var/artifacts/datasets/fresh-rom-r2/supplements/supplement_03_rom
python3 scripts/validate_datasets.py data/catalogs/fresh-rom-r2.json data/catalogs/fresh-cmake-r2.json data/catalogs/fresh-curl-r1.json
```

Frankie 目前還需先取得 catalog 對應 archive；`download_url` 尚為 null，不宣稱他已能直接下載。可在自己的機器依全新 factory 重建，或後續接團隊 artifact 交件。

## 下一輪仍須完成

Q1–Q5 事實收集與嚴格 Verifier、三個獨立 profile 與確定性判定、舊 Claim、AI 自主調查與引用驗證、完整補件重判/摘要、九格工程及至少三次 Live AI 驗收。OpenAI 環境由 Horace 設定完成後通知，尚未讀到 key 時不做 Live 成功宣稱。
