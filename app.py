import html
import logging
import time
import threading
import streamlit as st
from pipeline.graph import run_pipeline
from agents.chat_agent import chat_agent
from database import get_all_reviews, get_review_by_id

logging.getLogger("httpx").setLevel(logging.WARNING)

st.set_page_config(
    page_title="CodeGuard · AI Code Review",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* === Base === */
html, body { background-color: #0d1117 !important; }
.stApp { background-color: #0d1117 !important; }
.stApp > header, [data-testid="stHeader"] {
    background-color: #0d1117 !important;
    box-shadow: none !important;
    border-bottom: 1px solid #21262d !important;
}
.block-container { padding-top: 1.5rem !important; max-width: 1200px; }
.main { background-color: #0d1117 !important; }

/* === Sidebar === */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0f1626 0%, #0d1117 100%) !important;
    border-right: 1px solid #21262d !important;
}
section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] span,
section[data-testid="stSidebar"] div { color: #c9d1d9; }
section[data-testid="stSidebar"] hr { border-color: #21262d !important; margin: 12px 0 !important; }

/* === Tabs === */
.stTabs [data-baseweb="tab-list"] {
    background: #161b22 !important;
    border-radius: 10px !important;
    padding: 4px !important;
    border: 1px solid #21262d !important;
    gap: 3px !important;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 7px !important;
    color: #8b949e !important;
    font-weight: 500 !important;
    border: none !important;
    background: transparent !important;
    padding: 8px 16px !important;
    font-size: 14px !important;
}
.stTabs [aria-selected="true"] {
    background: #21262d !important;
    color: #58a6ff !important;
    font-weight: 600 !important;
}
.stTabs [data-baseweb="tab-panel"] { padding-top: 16px !important; }

/* === Text area === */
.stTextArea textarea {
    background-color: #161b22 !important;
    border: 1px solid #30363d !important;
    color: #c9d1d9 !important;
    border-radius: 8px !important;
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Fira Code', monospace !important;
    font-size: 13px !important;
    line-height: 1.6 !important;
}
.stTextArea textarea:focus {
    border-color: #58a6ff !important;
    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.1) !important;
}
.stTextArea textarea::placeholder { color: #484f58 !important; }

/* === Buttons === */
.stButton > button {
    background: linear-gradient(135deg, #238636 0%, #2ea043 100%) !important;
    color: #fff !important;
    border: 1px solid #2ea043 !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    letter-spacing: 0.3px !important;
    transition: all 0.2s ease !important;
    padding: 8px 20px !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #2ea043 0%, #3fb950 100%) !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 14px rgba(46, 160, 67, 0.35) !important;
}
.stButton > button:active { transform: translateY(0px) !important; }

/* === Radio === */
[data-testid="stRadio"] > div { gap: 8px !important; }
[data-testid="stRadio"] label { color: #c9d1d9 !important; }
[data-testid="stRadio"] [data-baseweb="radio"] div { border-color: #30363d !important; }

/* === File uploader === */
[data-testid="stFileUploader"] {
    background: #161b22 !important;
    border: 2px dashed #30363d !important;
    border-radius: 10px !important;
    padding: 8px !important;
}
[data-testid="stFileUploadDropzone"]:hover { border-color: #58a6ff !important; }

/* === Expander === */
[data-testid="stExpander"] {
    background: #161b22 !important;
    border: 1px solid #21262d !important;
    border-radius: 10px !important;
    overflow: hidden !important;
    margin-bottom: 8px !important;
}
[data-testid="stExpander"] summary {
    color: #c9d1d9 !important;
    font-weight: 500 !important;
    padding: 12px 16px !important;
}
[data-testid="stExpander"] summary:hover { background: #21262d !important; }
[data-testid="stExpander"] svg { fill: #8b949e !important; }

/* === Alerts === */
[data-testid="stAlert"] { border-radius: 8px !important; }
.stSuccess { background: rgba(63,185,80,0.1) !important; border: 1px solid rgba(63,185,80,0.3) !important; color: #3fb950 !important; border-radius: 8px !important; }
.stError   { background: rgba(248,81,73,0.1) !important;  border: 1px solid rgba(248,81,73,0.3) !important;  color: #f85149 !important; border-radius: 8px !important; }
.stWarning { background: rgba(210,153,34,0.1) !important; border: 1px solid rgba(210,153,34,0.3) !important; color: #d29922 !important; border-radius: 8px !important; }

/* === Chat === */
[data-testid="stChatMessage"] {
    background: #161b22 !important;
    border: 1px solid #21262d !important;
    border-radius: 12px !important;
    margin-bottom: 8px !important;
}
[data-testid="stChatInput"] textarea {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    color: #c9d1d9 !important;
    border-radius: 10px !important;
}
[data-testid="stChatInput"] textarea:focus { border-color: #58a6ff !important; }

/* === Code blocks === */
[data-testid="stCode"] pre, .stCode pre {
    background: #161b22 !important;
    border: 1px solid #21262d !important;
    border-radius: 8px !important;
}

/* === Divider === */
hr { border-color: #21262d !important; margin: 16px 0 !important; }

/* === Scrollbar === */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #484f58; }

/* ── Custom components ── */
.cg-logo-text {
    font-size: 1.5rem;
    font-weight: 800;
    background: linear-gradient(135deg, #58a6ff, #79c0ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}
.cg-section-title {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: #8b949e;
    margin-bottom: 10px;
    margin-top: 4px;
}
.cg-stat-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 14px;
    background: #21262d;
    border-radius: 8px;
    margin-bottom: 6px;
}
.cg-pipeline-step {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 5px 0;
}
.cg-pipeline-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #58a6ff;
    flex-shrink: 0;
    margin-top: 5px;
}
.cg-metric-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 22px 24px;
    text-align: center;
}
.cg-metric-label {
    color: #8b949e;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-bottom: 10px;
}
.cg-metric-value {
    font-size: 26px;
    font-weight: 800;
    color: #c9d1d9;
    line-height: 1;
}
.cg-agent-card {
    display: flex;
    align-items: center;
    gap: 14px;
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 13px 18px;
    margin-bottom: 8px;
    transition: all 0.3s ease;
}
.cg-agent-card.running {
    border-color: #58a6ff;
    background: linear-gradient(135deg, #161b22 0%, #0d1f35 100%);
    box-shadow: 0 0 24px rgba(88, 166, 255, 0.08);
}
.cg-agent-card.done {
    border-color: #238636;
    background: linear-gradient(135deg, #161b22 0%, #0d2418 100%);
}
.cg-agent-card.pending { opacity: 0.4; }
.cg-agent-icon { font-size: 1.3rem; min-width: 28px; text-align: center; }
.cg-agent-info { flex: 1; }
.cg-agent-name { font-weight: 600; color: #c9d1d9; font-size: 14px; }
.cg-agent-status-text { font-size: 12px; margin-top: 2px; }
.cg-agent-indicator { min-width: 24px; text-align: center; font-size: 16px; }
.cg-spinner {
    display: inline-block;
    width: 18px;
    height: 18px;
    border: 2px solid #58a6ff;
    border-top-color: transparent;
    border-radius: 50%;
    animation: cgSpin 0.8s linear infinite;
    vertical-align: middle;
}
@keyframes cgSpin { to { transform: rotate(360deg); } }
.cg-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 20px 24px;
}
.cg-pre {
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Fira Code', monospace;
    font-size: 13px;
    line-height: 1.65;
    white-space: pre-wrap;
    word-break: break-word;
    color: #c9d1d9;
    margin: 0;
}
.cg-history-empty {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 56px 24px;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# ── Session state ─────────────────────────────────────────────────────────────
for _k, _v in [("review_result", None), ("chat_history", []), ("chat_messages", [])]:
    if _k not in st.session_state:
        st.session_state[_k] = _v

# ── Constants ─────────────────────────────────────────────────────────────────
AGENTS = [
    ("🔒", "Security Agent",  "Scans for vulnerabilities & secrets"),
    ("✨", "Quality Agent",   "Reviews code quality & best practices"),
    ("🧪", "Test Agent",      "Generates pytest / Jest unit tests"),
    ("🔧", "Fix Agent",       "Rewrites code with all issues fixed"),
    ("📋", "Summary Agent",   "Compiles the final review report"),
]

BADGE = {
    "high":   ("rgba(248,81,73,0.15)",  "#f85149", "rgba(248,81,73,0.3)"),
    "medium": ("rgba(210,153,34,0.15)", "#d29922", "rgba(210,153,34,0.3)"),
    "low":    ("rgba(88,166,255,0.15)", "#58a6ff", "rgba(88,166,255,0.3)"),
    "clean":  ("rgba(63,185,80,0.15)",  "#3fb950", "rgba(63,185,80,0.3)"),
}

EXT_MAP = {
    "python": "py", "javascript": "js", "typescript": "ts",
    "java": "java", "go": "go", "c++": "cpp", "c": "c",
    "c#": "cs", "ruby": "rb", "php": "php",
}

LANG_HIGHLIGHT = {
    "python": "python", "javascript": "javascript", "typescript": "typescript",
    "java": "java", "go": "go", "c++": "cpp", "c": "c",
    "c#": "csharp", "ruby": "ruby", "php": "php",
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def sec_level(text: str) -> tuple:
    t = (text or "").upper()
    if "HIGH"   in t: return "HIGH",   "high"
    if "MEDIUM" in t: return "MEDIUM", "medium"
    if "LOW"    in t: return "LOW",    "low"
    return "CLEAN", "clean"


def q_score(text: str) -> str:
    for ln in (text or "").split("\n"):
        if "QUALITY_SCORE:" in ln:
            return ln.replace("QUALITY_SCORE:", "").strip()
    return "N/A"


def code_lang(lang: str) -> str:
    return LANG_HIGHLIGHT.get((lang or "").lower(), "text")


def file_ext(lang: str) -> str:
    return EXT_MAP.get((lang or "").lower(), "txt")


def agents_progress_html(current: int, done: int) -> str:
    cards = []
    for i, (icon, name, desc) in enumerate(AGENTS):
        if i < done:
            cls          = "done"
            status_html  = '<span style="color:#3fb950">✓ Complete</span>'
            indicator    = "✅"
        elif i == current:
            cls          = "running"
            status_html  = '<span style="color:#58a6ff">Running…</span>'
            indicator    = '<span class="cg-spinner"></span>'
        else:
            cls          = "pending"
            status_html  = '<span style="color:#484f58">Pending</span>'
            indicator    = '<span style="color:#484f58">○</span>'

        cards.append(f"""
<div class="cg-agent-card {cls}">
  <div class="cg-agent-icon">{icon}</div>
  <div class="cg-agent-info">
    <div class="cg-agent-name">{name}</div>
    <div class="cg-agent-status-text">{status_html}</div>
  </div>
  <div class="cg-agent-indicator">{indicator}</div>
</div>""")
    return "\n".join(cards)


def pre_card(text: str):
    escaped = html.escape(text or "No content generated.")
    st.markdown(
        f'<div class="cg-card"><pre class="cg-pre">{escaped}</pre></div>',
        unsafe_allow_html=True,
    )


def inline_badge(label: str, kind: str) -> str:
    bg, color, border = BADGE.get(kind, BADGE["clean"])
    return (
        f'<span style="background:{bg};color:{color};border:1px solid {border};'
        f'padding:3px 12px;border-radius:20px;font-size:11px;font-weight:700;'
        f'letter-spacing:0.5px">{html.escape(label)}</span>'
    )

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
<div style="display:flex;align-items:center;gap:12px;padding-bottom:16px;
            border-bottom:1px solid #21262d;margin-bottom:16px">
  <span style="font-size:2rem">🛡️</span>
  <span class="cg-logo-text">CodeGuard</span>
</div>
<p style="color:#8b949e;font-size:13px;margin-top:0;line-height:1.55">
  AI-powered multi-agent code security &amp; quality review.
  Powered by <strong style="color:#c9d1d9">LangGraph</strong>
  &amp; <strong style="color:#c9d1d9">Claude</strong>.
</p>""", unsafe_allow_html=True)

    # ── Stats ──────────────────────────────────────────────────────────────────
    all_reviews = get_all_reviews()
    n_reviews   = len(all_reviews)

    st.markdown('<div class="cg-section-title" style="margin-top:8px">Overview</div>',
                unsafe_allow_html=True)

    st.markdown(f"""
<div class="cg-stat-row">
  <span style="color:#8b949e;font-size:13px">Total Reviews</span>
  <span style="color:#58a6ff;font-weight:700;font-size:18px">{n_reviews}</span>
</div>""", unsafe_allow_html=True)

    if all_reviews:
        langs = sorted({r[2] for r in all_reviews if r[2]})
        langs_display = ", ".join(langs[:4]) + ("…" if len(langs) > 4 else "")
        st.markdown(f"""
<div class="cg-stat-row">
  <span style="color:#8b949e;font-size:13px">Languages</span>
  <span style="color:#79c0ff;font-size:12px;font-weight:600;text-align:right;max-width:120px">{html.escape(langs_display)}</span>
</div>""", unsafe_allow_html=True)

    st.markdown('<hr>', unsafe_allow_html=True)

    # ── Pipeline ───────────────────────────────────────────────────────────────
    st.markdown('<div class="cg-section-title">Agent Pipeline</div>', unsafe_allow_html=True)

    for icon, name, desc in AGENTS:
        st.markdown(f"""
<div class="cg-pipeline-step">
  <div class="cg-pipeline-dot"></div>
  <div>
    <div style="color:#c9d1d9;font-size:13px;font-weight:500">{icon} {name}</div>
    <div style="color:#484f58;font-size:11px;margin-top:1px">{desc}</div>
  </div>
</div>""", unsafe_allow_html=True)

    st.markdown('<hr>', unsafe_allow_html=True)
    st.markdown("""
<p style="color:#484f58;font-size:11px;text-align:center;margin:0;line-height:1.7">
  CodeGuard v1.0<br>
  LangGraph · claude-sonnet-4-5
</p>""", unsafe_allow_html=True)

# ── Main tabs ─────────────────────────────────────────────────────────────────
review_tab, history_tab = st.tabs(["🔍  Code Review", "📜  Review History"])

# ══════════════════════════════════════════════════════════════════════════════
# REVIEW TAB
# ══════════════════════════════════════════════════════════════════════════════
with review_tab:
    st.markdown("""
<h2 style="color:#c9d1d9;margin-bottom:2px;font-size:1.6rem;font-weight:700">
  Submit Your Code
</h2>
<p style="color:#8b949e;margin-top:0;margin-bottom:20px;font-size:14px">
  Paste or upload code to run a full AI-powered review across 5 specialized agents.
</p>""", unsafe_allow_html=True)

    # ── Input method ──────────────────────────────────────────────────────────
    c_radio, _ = st.columns([3, 7])
    with c_radio:
        input_method = st.radio(
            "Input method",
            ["Paste Code", "Upload File"],
            horizontal=True,
            label_visibility="collapsed",
        )

    code_input = ""

    if input_method == "Paste Code":
        code_input = st.text_area(
            "Code",
            height=280,
            placeholder=(
                "# Paste your code here…\n"
                "# Supports Python, JavaScript, Java, TypeScript, Go, C++, Ruby, PHP, and more"
            ),
            label_visibility="collapsed",
        )
    else:
        uploaded_file = st.file_uploader(
            "Upload a code file",
            type=["py", "js", "java", "ts", "cpp", "c", "cs", "go", "rb", "php"],
            label_visibility="collapsed",
        )
        if uploaded_file is not None:
            code_input = uploaded_file.read().decode("utf-8")
            st.code(code_input, language="python")

    btn_col, hint_col = st.columns([2, 8])
    with btn_col:
        review_clicked = st.button(
            "🔍  Run Code Review", type="primary", use_container_width=True
        )
    with hint_col:
        if not code_input.strip():
            st.markdown(
                '<p style="color:#484f58;padding:10px 0;font-size:13px">'
                "← Paste or upload code, then click to start the review</p>",
                unsafe_allow_html=True,
            )

    # ── Pipeline execution ────────────────────────────────────────────────────
    if review_clicked:
        if not code_input.strip():
            st.error("Please paste or upload some code before reviewing.")
        else:
            st.markdown('<hr>', unsafe_allow_html=True)
            st.markdown('<div class="cg-section-title">Agent Progress</div>',
                        unsafe_allow_html=True)

            agents_ph = st.empty()
            status_ph = st.empty()

            result_holder: dict = {}
            done_event = threading.Event()

            def _run_pipeline():
                result_holder["r"] = run_pipeline(code_input)
                done_event.set()

            threading.Thread(target=_run_pipeline, daemon=True).start()

            # Estimated cumulative time thresholds (seconds) for each agent boundary
            EST_TOTAL = 45.0
            THRESHOLDS = [t * EST_TOTAL for t in [0.20, 0.40, 0.65, 0.85, 1.01]]

            t0 = time.time()
            while not done_event.wait(timeout=0.35):
                elapsed = time.time() - t0
                current = 0
                for i, thresh in enumerate(THRESHOLDS):
                    if elapsed >= thresh:
                        current = min(i + 1, len(AGENTS) - 1)

                agents_ph.markdown(
                    agents_progress_html(current, current),
                    unsafe_allow_html=True,
                )
                status_ph.markdown(
                    f'<p style="color:#8b949e;font-size:13px;margin-top:4px">'
                    f'Running {AGENTS[current][1]}… ({int(time.time() - t0)}s elapsed)</p>',
                    unsafe_allow_html=True,
                )

            result = result_holder.get("r") or {"error": "Pipeline returned no result."}

            if "error" in result:
                agents_ph.empty()
                status_ph.error(f"❌ {result['error']}")
            else:
                agents_ph.markdown(
                    agents_progress_html(-1, len(AGENTS)),
                    unsafe_allow_html=True,
                )
                status_ph.success("✅ Review complete! Results are shown below.")
                st.session_state.review_result = result
                st.session_state.chat_history   = []
                st.session_state.chat_messages  = []

    # ── Results ───────────────────────────────────────────────────────────────
    if st.session_state.review_result:
        r = st.session_state.review_result

        if "pii_warning" in r:
            pii_types = ", ".join(r["pii_warning"].keys())
            st.warning(
                f"⚠️ **PII Detected:** Your code appears to contain {pii_types}. "
                "Consider removing sensitive data before sharing."
            )

        st.markdown('<hr>', unsafe_allow_html=True)

        # ── Metric cards ──────────────────────────────────────────────────────
        lang_val  = r.get("language", "Unknown") or "Unknown"
        sl, sc    = sec_level(r.get("security_findings", ""))
        score_val = q_score(r.get("quality_findings", ""))
        _, sec_color, _ = BADGE.get(sc, BADGE["clean"])

        m1, m2, m3 = st.columns(3)
        with m1:
            st.markdown(f"""
<div class="cg-metric-card">
  <div class="cg-metric-label">Language</div>
  <div class="cg-metric-value">{html.escape(lang_val)}</div>
</div>""", unsafe_allow_html=True)
        with m2:
            st.markdown(f"""
<div class="cg-metric-card">
  <div class="cg-metric-label">Security Risk</div>
  <div class="cg-metric-value" style="color:{sec_color}">{sl}</div>
</div>""", unsafe_allow_html=True)
        with m3:
            st.markdown(f"""
<div class="cg-metric-card">
  <div class="cg-metric-label">Quality Score</div>
  <div class="cg-metric-value">{html.escape(score_val)}</div>
</div>""", unsafe_allow_html=True)

        st.markdown("<div style='margin-top:20px'></div>", unsafe_allow_html=True)

        # ── Result tabs ───────────────────────────────────────────────────────
        rep_t, fix_t, tst_t, sec_t, qual_t, chat_t = st.tabs([
            "📋 Full Report",
            "🔧 Fixed Code",
            "🧪 Tests",
            "🔒 Security",
            "✨ Quality",
            "💬 Chat",
        ])

        with rep_t:
            st.markdown('<div class="cg-section-title">Full Review Report</div>',
                        unsafe_allow_html=True)
            pre_card(r.get("final_report", ""))

        with fix_t:
            st.markdown('<div class="cg-section-title">Fixed Code</div>',
                        unsafe_allow_html=True)
            fixed_code = r.get("fixed_code", "") or "# No fixed code generated."
            st.code(fixed_code, language=code_lang(lang_val))
            if fixed_code.strip():
                st.download_button(
                    "⬇️  Download Fixed Code",
                    data=fixed_code,
                    file_name=f"fixed_code.{file_ext(lang_val)}",
                    mime="text/plain",
                )

        with tst_t:
            st.markdown('<div class="cg-section-title">Generated Unit Tests</div>',
                        unsafe_allow_html=True)
            tests_code = r.get("test_findings", "") or "# No tests generated."
            st.code(tests_code, language=code_lang(lang_val))
            if tests_code.strip():
                st.download_button(
                    "⬇️  Download Tests",
                    data=tests_code,
                    file_name=f"test_generated.{file_ext(lang_val)}",
                    mime="text/plain",
                )

        with sec_t:
            st.markdown('<div class="cg-section-title">Security Analysis</div>',
                        unsafe_allow_html=True)
            pre_card(r.get("security_findings", ""))

        with qual_t:
            st.markdown('<div class="cg-section-title">Quality Analysis</div>',
                        unsafe_allow_html=True)
            pre_card(r.get("quality_findings", ""))

        with chat_t:
            st.markdown("""
<h3 style="color:#c9d1d9;margin-bottom:4px;font-size:1.1rem;font-weight:700">
  💬 Chat with CodeGuard
</h3>
<p style="color:#8b949e;font-size:13px;margin-top:0;margin-bottom:16px">
  Ask follow-up questions about vulnerabilities, quality findings, or the suggested fixes.
</p>""", unsafe_allow_html=True)

            for msg in st.session_state.chat_messages:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

            if user_q := st.chat_input("Ask anything about your code review…"):
                st.session_state.chat_messages.append({"role": "user", "content": user_q})
                with st.chat_message("user"):
                    st.markdown(user_q)

                with st.chat_message("assistant"):
                    with st.spinner("Thinking…"):
                        response, st.session_state.chat_history = chat_agent(
                            user_q,
                            st.session_state.review_result,
                            st.session_state.chat_history,
                        )
                    st.markdown(response)

                st.session_state.chat_messages.append(
                    {"role": "assistant", "content": response}
                )

# ══════════════════════════════════════════════════════════════════════════════
# HISTORY TAB
# ══════════════════════════════════════════════════════════════════════════════
with history_tab:
    st.markdown("""
<h2 style="color:#c9d1d9;margin-bottom:2px;font-size:1.6rem;font-weight:700">
  Review History
</h2>
<p style="color:#8b949e;margin-top:0;margin-bottom:20px;font-size:14px">
  All past code reviews. Click <em>Load</em> to restore any result in the Code Review tab.
</p>""", unsafe_allow_html=True)

    reviews = get_all_reviews()

    if not reviews:
        st.markdown("""
<div class="cg-history-empty">
  <div style="font-size:3rem;margin-bottom:16px">🛡️</div>
  <div style="font-size:16px;font-weight:600;color:#8b949e;margin-bottom:6px">
    No reviews yet
  </div>
  <div style="font-size:13px;color:#484f58">
    Submit some code in the Code Review tab to get started.
  </div>
</div>""", unsafe_allow_html=True)
    else:
        for review in reviews:
            review_id, timestamp, language, final_report_text = review
            full_text   = final_report_text or ""
            preview_raw = full_text[:240].strip()
            preview     = html.escape(preview_raw + ("…" if len(full_text) > 240 else ""))
            sl, sc      = sec_level(full_text)
            sec_bg, sec_color, sec_border = BADGE.get(sc, BADGE["clean"])
            lang_safe = html.escape(language or "Unknown")

            with st.expander(f"#{review_id} · {timestamp} · {language or 'Unknown'}"):
                info_col, btn_col = st.columns([5, 1])

                with info_col:
                    st.markdown(f"""
<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
  <span style="background:rgba(88,166,255,0.1);color:#58a6ff;
               border:1px solid rgba(88,166,255,0.3);
               padding:3px 12px;border-radius:20px;
               font-size:11px;font-weight:700">{lang_safe}</span>
  <span style="background:{sec_bg};color:{sec_color};
               border:1px solid {sec_border};
               padding:3px 12px;border-radius:20px;
               font-size:11px;font-weight:700">Security: {sl}</span>
</div>
<div style="color:#8b949e;font-size:13px;font-family:monospace;
            line-height:1.55;white-space:pre-wrap">{preview}</div>""",
                        unsafe_allow_html=True)

                with btn_col:
                    if st.button("Load", key=f"load_{review_id}", type="primary"):
                        full = get_review_by_id(review_id)
                        if full:
                            st.session_state.review_result = {
                                "code":               "",
                                "language":           full[2],
                                "security_findings":  full[3],
                                "quality_findings":   full[4],
                                "test_findings":      full[5],
                                "fixed_code":         full[6],
                                "final_report":       full[7],
                            }
                            st.session_state.chat_history  = []
                            st.session_state.chat_messages = []
                            st.success(
                                f"Review #{review_id} loaded! "
                                "Switch to the Code Review tab to see the full results."
                            )
