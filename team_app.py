"""Hosted entry point. No workspace data is accessed before authorization."""
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
import streamlit as st
from cvevidence.web_access import principal, release_label, deployment_policy, bind_session, account_root
from cvevidence.product_style import apply_style
apply_style(st)

try:
    allowed = deployment_policy(st.secrets)
except (KeyError, ValueError, FileNotFoundError):
    bind_session(st.session_state,None)
    st.error("團隊測試站尚未完成登入設定，暫不開放工作台。")
    st.stop()

if not st.user.is_logged_in:
    bind_session(st.session_state,None)
    st.title("CVEvidence")
    st.write("團隊測試站 · 使用受邀的 Google 帳號登入")
    st.button("使用 Google 登入", on_click=st.login, args=("google",))
    st.stop()
try:
    identity = principal(dict(st.user), allowed)
except ValueError:
    bind_session(st.session_state,None)
    st.error("此帳號尚未獲得測試站存取權。")
    st.button("登出", on_click=st.logout)
    st.stop()

bind_session(st.session_state,identity)

from cvevidence.runtime_guard import current
if not current():
    st.error("服務版本更新中，請等待重新部署完成。")
    st.stop()
from cvevidence.workspace import workspace
st.sidebar.subheader("◈ CVEvidence")
st.sidebar.caption("每個結論，都有證據。")
with st.sidebar.expander("版本資訊"):
    st.caption("部署版本：" + release_label(os.environ.get("CVEVIDENCE_RELEASE_SHA")))
st.sidebar.button("登出", on_click=st.logout)
root = Path(os.environ.get("CVEVIDENCE_WEB_STORE", "var/team-runtime"))
try:
    owned_root=account_root(root,identity)
except (ValueError,OSError):
    st.error("帳號資料目錄無法安全開啟，請聯絡管理員；未載入查核資料。")
    st.stop()
workspace(st, store_root=owned_root)
