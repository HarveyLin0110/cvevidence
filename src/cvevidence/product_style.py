"""Static product styling only; never interpolates evidence or user text."""
def apply_style(st):
    st.markdown('''<style>
    .stApp {background:#f7faf9;color:#203a35}
    .stApp, .stApp p, .stApp button, .stApp input, .stApp textarea, .stApp h1, .stApp h2, .stApp h3 {font-family:"Segoe UI","Microsoft JhengHei",sans-serif}
    [data-testid="stSidebar"] {background:#15303c;border-right:1px solid #294650}
    [data-testid="stSidebar"] p,[data-testid="stSidebar"] label {color:#dcebe8}
    [data-testid="stSidebar"] button {background:#204550;color:#f5fbfa;border-color:#41616a}
    [data-testid="stSidebar"] button:disabled {color:#91a4ab;background:#19343f}
    [data-testid="stSidebar"] [data-testid="stExpander"] {background:#193943;border-color:#41616a}
    [data-testid="stSidebar"] [data-baseweb="select"] {color:#253e37}
    [data-testid="stSidebar"] [data-baseweb="select"] div {color:#253e37}
    [data-testid="stSidebar"] h2,[data-testid="stSidebar"] h3 {color:white}
    .block-container {max-width:1180px;padding-top:2.2rem;padding-bottom:3rem}
    h1 {font-size:2rem!important;letter-spacing:-.025em}
    h2 {font-size:1.45rem!important} h3 {font-size:1.15rem!important}
    [data-testid="stMain"] p {line-height:1.75}
    [data-testid="stCaptionContainer"] {font-size:.86rem}
    [data-testid="stMain"] [data-testid="stCaptionContainer"] p {color:#52675f}
    [data-testid="stMetric"] {background:white;border:1px solid #dce7e2;border-radius:12px;padding:14px 18px}
    [data-testid="stMetricValue"] {font-size:1.7rem}
    [data-testid="stExpander"] {background:white;border-color:#dce7e2;border-radius:10px}
    [data-baseweb="tab-list"] {gap:18px;border-bottom:1px solid #dce7e2}
    .stApp button[kind="primary"], .stApp button[data-testid="stBaseButton-primary"] {background:#246e5c!important;border-color:#246e5c!important;color:white}
    button[kind="secondary"] {border-color:#cadbd3;border-radius:8px}
    @media(max-width:640px){.block-container{padding:1.2rem 1rem}h1{font-size:1.55rem!important}}
    </style>''', unsafe_allow_html=True)
