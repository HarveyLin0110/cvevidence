# Tailscale 團隊測試站
更新：2026-09-12，部署程式 SHA：477dac2e1da137f914671c0e3cfe025ce03e9186（PR #6，測試站版本，尚未正式 release）。

入口：https://laptop-5tcfdp5e.tailea98bd.ts.net/

## 存取邊界
- Windows Tailscale Funnel HTTPS443 → Windows localhost8507 → WSL team_app.py。
- 訪客不需安裝Tailscale。網址對公網可達，工具使用仍需Google登入、verified email及私下配置的三位受邀帳號。
- 使用 cvevidence-demo / CVEvidence Local Demo 專用client，只新增此HTTPS oauth2callback；保留原有callback，不改其他專案client。
- 私密設定只存部署 checkout 的 .streamlit/secrets.toml，權限600；新的隨機cookie secret。未複製舊程式或舊runtime。
- 獨立部署目錄 /home/frankie/projects/cvevidence-team-site；資料 var/team-runtime/<subject-sha256>；不連8505/8506。
- 上傳限制32MB，可容納目前正式demo工程包。完整工程/AI尚未接線，介面明示未執行。

## 已驗證
- Funnel status 對443僅代理127.0.0.1:8507；HTTPS HTTP200。
- 真實Chrome未登入看到登入頁，登入sykman帳號後看到固定SHA與空白個人歷史。
- Google OIDC帳號選擇與回呼成功，不需改原client secret。
- 公網建立情境DRAFT成功，顯示缺件引導、補件入口與下載入口；未虛構分析結果。
- 72單元/整合測試是程式驗證，不代表三帳號完整越權/下載測試或容量驗收。

## 操作
Windows PowerShell檢查：
```powershell
tailscale funnel status
Invoke-WebRequest http://127.0.0.1:8507/_stcore/health
```
停止此公開入口（保留其他設定）：
```powershell
tailscale funnel --https=443 off
```
恢復前先確認8507仍為本專案team_app、Google設定完整：
```powershell
tailscale funnel --bg --https=443 http://127.0.0.1:8507
```
不要使用funnel reset，不要把8505/8506換成公開target。

目前WSL程序背景執行，尚未建立開機自動恢復；電腦關機、休眠、WSL關閉或網路中斷時網站不可用。
此位址以裝置/tailnet名稱為基礎，重新命名會影響URL與Google callback，不應任意改名。
持續展示需要保持此機在線；長期正式站可移到常駐Linux主機。Funnel提供HTTPS轉送，不等於主機隔離、工作佇列或容量保證。

## 更新方式與待驗收
- 部署checkout固定SHA，不跟工作分支熱更新；新版本先整合驗收，再停舊程序、切到經核准SHA、啟動並確認頁面版本。
- 保留原資料與備份；schema不相容需遷移/回退演練。不要git clean移除runtime。
- 待辦：三帳號交叉run/下載測試、真實分析接線、併發/配額、開機恢復、全流程回退。
- 詳細正式放行門檻見live-site.md。網站live與AI LIVE狀態分開，不冒稱核心已完成。

官方：https://tailscale.com/docs/reference/tailscale-cli/funnel
