# 持續 Demo 與正式網站驗收
日期：2026-09-12。負責：整合端；網站使用目前 Python/Streamlit 產品，同一程式逐里程碑演進。

最新部署：已建立 Tailscale Funnel 測試入口並完成一次真實 Google 登入，詳見 [Tailscale部署紀錄](tailscale-demo.md)。以下「尚未取得」描述保留為原始規劃背景，最新事實以部署紀錄為準；正式驗收仍未完成。

## 現況與發布邊界
- 本機整合 8505、Frankie 開發 8506 維持獨立。team_app.py 是新的受邀 Google OIDC 入口。
- 此次新增登入門檻與依 Google subject 區分的資料儲存位置；不是已完成雲端部署或登入端對端驗收。
- 尚未取得固定網域、主機與新 Demo OAuth 設定，因此沒有可宣稱已上線的團隊網址。
- 收件/來源/補件與真正 Q1–Q5、Verifier、判定、LIVE AI 分開驗收。未接通保持 NOT_RUN。
- 不修改既有 OAuth client。使用 cvevidence-demo 的專用 client，測試與正式 callback 精確列入。
- 網站 live 表示網站在線；AI LIVE 僅表示當次真實 API 執行，不能混用。

## 環境
| 環境 | 內容 | 發布 |
| --- | --- | --- |
| 個人開發 | 工作分支、個人資料 | 本機8506 |
| 整合驗收 | 兩方固定 commit 合併 | 本機8505 |
| 團隊測試站 | 已通過整合的 main SHA；獨立資料與 secret | 固定 HTTPS 測試域名 |
| 正式展示站 | 驗收確認的相同 SHA；獨立資料與 secret | release tag 固定版本 |

推薦常駐 Linux 主機，HTTPS 反向代理支援 WebSocket；Python、readelf、unsquashfs 與持久資料磁碟。平台未選定前不開付費資源。
Cloudflare named tunnel 可作 HTTPS 入口；Quick Tunnel 只適合短期測試，不能作最終固定網址或可靠性保證。

## 設定與啟動
1. 在乾淨、獨立部署 checkout 固定欲發布 SHA，執行 python -m pip install -r deploy/requirements.txt 及 python -m pip install -e .。
2. 將 deploy/secrets.example.toml 複製至該 checkout 的 .streamlit/secrets.toml，填專用 client、32字元以上隨機 cookie secret、HTTPS callback、三位受邀成員 email；權限600，不進Git。
3. 設定 CVEVIDENCE_WEB_STORE 為部署專用持久目錄，CVEVIDENCE_RELEASE_SHA 為完整 commit；不要掛載本機 var/runtime 或開發者 home。
4. 執行 python -m streamlit run team_app.py --server.address 127.0.0.1 --server.port 8507 --server.headless true。
5. HTTPS proxy 僅指向8507；保留 CORS/XSRF；不要直接公開 runner_app.py、8505、8506。
6. 完成下列驗收才公布網址。OAuth secret、API key、tunnel token 僅在主機 secret配置。
7. 正式站部署同一已驗收 SHA；版本更新重啟程序，不能依賴 Streamlit 快取熱載入。

## 最終成果的放行門檻
| 關卡 | 必須留下的證據 | 阻擋發布 |
| --- | --- | --- |
| 可重現建置 | SHA、依賴版本、乾淨安裝與 CI | CI失敗或版本不明 |
| 登入與隔離 | 未登入不能讀/下載/提交；非allowlist拒絕；兩帳號交叉run測試；登出重入 | 越權、回呼錯誤、session混用 |
| 使用流程 | 情境草稿→產品/版本/檔案→缺件→分析→報告→補件子run；手機/桌面 | 死路、錯誤崩頁、父結果被覆蓋 |
| 工程正確 | 正式12包hash；9初始分析+3補件；每個Q1–Q5及condition可追原文 | 以檔名猜verdict、完整性失败仍判定 |
| AI可信 | OFFLINE/LIVE/REPLAY獨立；模型/用量/耗時；錯引用拒絕；超時保留工程結果 | 假LIVE、未驗證引用、AI直接改工程結論 |
| 安全與容量 | 惡意archive/路徑/過量上傳；併發、disk/CPU/記憶體上限；secret不外洩 | 任意執行、跨使用者資料、無限制耗資源 |
| 展示與復原 | 顯示SHA；備份還原演練；上一版本回退；三位成員實際測試 | 無回退或資料不能讀 |

這張表是待驗收要求，不能當作已實作保證。現有 identity 單元測試不等於 OIDC/瀏覽器/下載隔離驗收。
目前每位使用者的完整資料獨立；團隊共用run需另設明確分享授權，不直接共用整個runtime。
目前還需資源配額、併發工作佇列、上傳隔離與部署層驗收，才適合常駐公開使用。

## 持續觀察與發布紀錄
- 每15分鐘既有整合巡檢追GitHub變更，不因遠端有commit就熱更新展示站。
- 里程碑PR記錄：來源SHA、整合SHA、受影響規則、測試命令/結果、已知缺口、回退SHA。
- 每次測試站發布記錄URL/部署SHA/時間；正式tag只能指向驗收通過的同一SHA。
- 錯誤回報用版本SHA、run/request ID、重現步驟、預期/實際；不貼secret或客戶原始檔。
- 失敗先停發布，保留失敗證據；回退程式與相容資料快照，避免直接覆蓋舊run。
- 團隊確認主要產品流程及最終Demo後才標準備完成；自動測試通過不代表人員已簽核。

## 官方依據
- https://docs.streamlit.io/develop/api-reference/user/st.login
- https://docs.streamlit.io/develop/concepts/connections/authentication
- https://developers.cloudflare.com/tunnel/setup/
