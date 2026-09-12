"""Hosted entry point. No workspace data is accessed before authorization."""
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
import streamlit as st
from cvevidence.web_access import principal, release_label
from cvevidence.product_style import apply_style
apply_style(st)

try:
    policy = st.secrets["deployment"]
    allowed = policy["allowed_emails"]
    auth = st.secrets["auth"]
    google = auth["google"]
    if (not isinstance(allowed, list) or not allowed
            or not auth["redirect_uri"].startswith("https://")
            or len(auth["cookie_secret"]) < 32
            or google["server_metadata_url"] != "https://accounts.google.com/.well-known/openid-configuration"
            or not google["client_id"] or not google["client_secret"]):
        raise ValueError("Incomplete configuration")
except (KeyError, ValueError, FileNotFoundError):
    st.error("團隊測試站尚未完成登入設定，暫不開放工作台。")
    st.stop()

if not st.user.is_logged_in:
    st.title("CVEvidence")
    st.write("團隊測試站 · 使用受邀的 Google 帳號登入")
    st.button("使用 Google 登入", on_click=st.login, args=("google",))
    st.stop()
try:
    identity = principal(dict(st.user), allowed)
except ValueError:
    st.error("此帳號尚未獲得測試站存取權。")
    st.button("登出", on_click=st.logout)
    st.stop()

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
workspace(st, store_root=root / identity)
