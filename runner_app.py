"""Local-only workspace. Never expose without adding authenticated per-run access."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent/"src"))
import streamlit as st
from cvevidence.runtime_guard import current
if not current():
    st.error("程式已更新，請重新啟動工作台服務再操作。既有資料保留。")
    st.code("python scripts/workspace_service.py restart")
    st.stop()
from cvevidence.workspace import workspace
workspace(st)
