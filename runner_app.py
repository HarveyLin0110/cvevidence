"""Local-only workspace. Never expose without adding authenticated per-run access."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent/"src"))
import streamlit as st
from cvevidence.workspace import workspace
workspace(st)
