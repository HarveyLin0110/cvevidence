"""Static product styling only; never interpolates evidence or user text."""
def apply_style(st):
    st.markdown('''<style>
    .stApp {background:#f7faf9;color:#203a35}
    .stApp, .stApp p, .stApp button, .stApp input, .stApp textarea, .stApp h1, .stApp h2, .stApp h3 {font-family:"Segoe UI","Microsoft JhengHei",sans-serif}
    [data-testid="stSidebar"] {background:#15303c;border-right:1px solid #294650}
    [data-testid="stSidebar"] p,[data-testid="stSidebar"] label {color:#dcebe8}
    [data-testid="stSidebar"] button {background:#204550;color:#f5fbfa;border-color:#41616a}
    [data-testid="stSidebar"] button:disabled {color:#91a4ab;background:#19343f}
    [data-testid="stSidebar"] [data-testid="stExpander"] {background:#f3f7f8;border:1px solid #a5bcc5;border-radius:10px;color:#203a35}
    [data-testid="stSidebar"] [data-testid="stExpander"] summary {background:#dce9ed;color:#183a45;border-radius:9px;padding:.8rem}
    [data-testid="stSidebar"] [data-testid="stExpander"] details[open] > summary {background:#c5dce3;border-bottom:2px solid #537e8e;border-radius:9px 9px 0 0}
    [data-testid="stSidebar"] [data-testid="stExpander"] p,
    [data-testid="stSidebar"] [data-testid="stExpander"] label,
    [data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stText"],
    [data-testid="stSidebar"] [data-testid="stExpander"] h3 {color:#203a35}
    [data-testid="stSidebar"] [data-testid="stExpander"] button p {color:#f5fbfa}
    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {color:#c9dde1}
    [data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stCaptionContainer"] p {color:#405c66}
    [data-testid="stSidebar"] [data-baseweb="select"] > div {background:#fff;border-color:#718c97}
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
    [data-testid="stMain"] [data-testid="stExpander"] summary {background:#eef4f2;border-radius:9px}
    [data-testid="stMain"] [data-testid="stExpander"] details[open] > summary {background:#dcece6;border-bottom:2px solid #789d8d;border-radius:9px 9px 0 0}
    [data-testid="stExpander"] summary:hover {filter:brightness(.96)}
    .stApp button:focus-visible,.stApp summary:focus-visible,.stApp input:focus-visible,.stApp textarea:focus-visible {outline:3px solid #337fac!important;outline-offset:3px}
    [data-testid="stText"] {line-height:1.8;overflow-wrap:anywhere}
    [data-testid="stText"] > span {color:inherit}
    [data-testid="stMain"] [data-testid="stVerticalBlockBorderWrapper"] {background:#fff}
    [class*="st-key-result_affected_"],[class*="st-key-pc_affected_"] {background:#fff3f2!important;border-left:4px solid #b42318!important;border-radius:10px}
    [class*="st-key-result_affected_"] [data-testid="stText"],
    [class*="st-key-pc_affected_"] [data-testid="stText"] {color:#a51d18!important;font-weight:600}
    [class*="st-key-result_pending_"],[class*="st-key-pc_pending_"] {background:#fffaf0!important;border-left:4px solid #946200!important;border-radius:10px}
    [class*="st-key-result_pending_"] [data-testid="stText"],
    [class*="st-key-pc_pending_"] [data-testid="stText"] {color:#785000!important}
    [data-baseweb="tab-list"] {gap:18px;border-bottom:1px solid #dce7e2}
    [data-baseweb="tab"][aria-selected="true"] {color:#195b49;font-weight:700;background:#e3f0ea;border-radius:8px 8px 0 0}
    [data-testid="stMain"] input,[data-testid="stMain"] textarea {color:#203a35;background:#fff}
    .stApp button[kind="primary"], .stApp button[data-testid="stBaseButton-primary"] {background:#246e5c!important;border-color:#246e5c!important;color:white}
    button[kind="secondary"] {border-color:#cadbd3;border-radius:8px}
    @media(max-width:640px){.block-container{padding:1.2rem 1rem}h1{font-size:1.55rem!important}}
    </style>''', unsafe_allow_html=True)
