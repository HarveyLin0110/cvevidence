"""Static product styling only; never interpolates evidence or user text."""
def apply_style(st):
    st.markdown('''<style>
    .stApp {background:#f7faf9;color:#203a35}
    [data-testid="stSidebar"] {background:#edf4f1;border-right:1px solid #dce7e2}
    .block-container {max-width:1180px;padding-top:2.2rem;padding-bottom:3rem}
    h1 {font-size:2rem!important;letter-spacing:-.025em}
    h2 {font-size:1.45rem!important} h3 {font-size:1.15rem!important}
    [data-testid="stMetric"] {background:white;border:1px solid #dce7e2;border-radius:12px;padding:14px 18px}
    [data-testid="stMetricValue"] {font-size:1.7rem}
    [data-testid="stExpander"] {background:white;border-color:#dce7e2;border-radius:10px}
    [data-baseweb="tab-list"] {gap:18px;border-bottom:1px solid #dce7e2}
    button[kind="primary"] {background:#246e5c;border-color:#246e5c}
    button[kind="secondary"] {border-color:#cadbd3;border-radius:8px}
    @media(max-width:640px){.block-container{padding:1.2rem 1rem}h1{font-size:1.55rem!important}}
    </style>''', unsafe_allow_html=True)
