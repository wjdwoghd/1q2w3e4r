"""Streamlit entry point. Explicit navigation hides legacy placeholder pages."""

import sys
from pathlib import Path

# Streamlit also supports invocation directly by script path from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st

from app.dashboard.view import render

st.set_page_config(page_title="SBOM 위험·개선 검증 조회", page_icon=":material/fact_check:", layout="wide")
st.navigation([st.Page(render, title="읽기 전용 Dashboard", default=True)], position="hidden").run()
