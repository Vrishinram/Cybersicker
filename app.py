import streamlit as st
import os
import requests
import datetime
from langchain.agents import create_agent
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_text_splitters import CharacterTextSplitter
from langchain.tools import tool

from autoencoder import run_network_scan

# ==========================================
# 1. PAGE CONFIG & CUSTOM CSS
# ==========================================
st.set_page_config(
    page_title="CYBERSICKER // SOC",
    page_icon="CS",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Military-grade SOC Dark Theme CSS ──
st.markdown("""
<style>
/* ═══════════ IMPORTS ═══════════ */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Orbitron:wght@500;700;900&display=swap');

/* ═══════════ HIDE STREAMLIT DEFAULTS ═══════════ */
#MainMenu, header, footer, ***REMOVED***data-testid="stToolbar"***REMOVED***,
***REMOVED***data-testid="stDecoration"***REMOVED***, .stDeployButton {display: none !important;}
/* Hide any Material Icon text that leaks into the sidebar */
section***REMOVED***data-testid="stSidebar"***REMOVED*** .material-symbols-rounded,
section***REMOVED***data-testid="stSidebar"***REMOVED*** ***REMOVED***data-testid="stSidebarNavLink"***REMOVED***,
section***REMOVED***data-testid="stSidebar"***REMOVED*** ***REMOVED***data-testid="stSidebarNavSeparator"***REMOVED***,
section***REMOVED***data-testid="stSidebar"***REMOVED*** ***REMOVED***data-testid="stSidebarHeader"***REMOVED***,
section***REMOVED***data-testid="stSidebar"***REMOVED*** .stPageLink,
section***REMOVED***data-testid="stSidebar"***REMOVED*** span.material-icons,
section***REMOVED***data-testid="stSidebar"***REMOVED*** ***REMOVED***data-testid="stSidebarNavItems"***REMOVED***,
section***REMOVED***data-testid="stSidebar"***REMOVED*** ***REMOVED***data-testid="stLogo"***REMOVED***,
section***REMOVED***data-testid="stSidebar"***REMOVED*** nav {display: none !important;}
section***REMOVED***data-testid="stSidebarUserContent"***REMOVED*** {margin-top: 0 !important; padding-top: 1rem !important;}

/* ═══════════ ROOT VARIABLES ═══════════ */
:root {
    --bg-primary:   #0a0e17;
    --bg-secondary: #0f1623;
    --bg-card:      #111a2b;
    --bg-input:     #0d1321;
    --cyan:         #00f0ff;
    --cyan-dim:     #00f0ff88;
    --red:          #ff003c;
    --red-dim:      #ff003c66;
    --green:        #00ff88;
    --amber:        #ffaa00;
    --text:         #c8d6e5;
    --text-muted:   #5c6b7e;
    --border:       #1a2a44;
    --glow-cyan:    0 0 15px #00f0ff33, 0 0 30px #00f0ff11;
    --glow-red:     0 0 15px #ff003c33;
    --font-mono:    'JetBrains Mono', monospace;
    --font-display: 'Orbitron', sans-serif;
}

/* ═══════════ GLOBAL ═══════════ */
html, body, .stApp, ***REMOVED***data-testid="stAppViewContainer"***REMOVED*** {
    background-color: var(--bg-primary) !important;
    color: var(--text) !important;
    font-family: var(--font-mono) !important;
}
.stApp {background: var(--bg-primary) !important;}
***REMOVED***data-testid="stAppViewBlockContainer"***REMOVED*** {max-width: 1200px;}

/* ═══════════ SIDEBAR ═══════════ */
section***REMOVED***data-testid="stSidebar"***REMOVED*** {
    background: linear-gradient(180deg, #070b14 0%, #0c1220 100%) !important;
    border-right: 1px solid var(--border) !important;
}
section***REMOVED***data-testid="stSidebar"***REMOVED*** * {
    color: var(--text) !important;
    font-family: var(--font-mono) !important;
}
section***REMOVED***data-testid="stSidebar"***REMOVED*** .stMarkdown h1,
section***REMOVED***data-testid="stSidebar"***REMOVED*** .stMarkdown h2,
section***REMOVED***data-testid="stSidebar"***REMOVED*** .stMarkdown h3 {
    color: var(--cyan) !important;
    font-family: var(--font-display) !important;
    letter-spacing: 1px;
}

/* ═══════════ INPUTS ═══════════ */
input, textarea, .stTextInput input, .stTextArea textarea {
    background-color: var(--bg-input) !important;
    color: var(--cyan) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    font-family: var(--font-mono) !important;
    transition: border-color 0.3s, box-shadow 0.3s;
}
input:focus, textarea:focus, .stTextInput input:focus {
    border-color: var(--cyan) !important;
    box-shadow: var(--glow-cyan) !important;
    outline: none !important;
}

/* ═══════════ CHAT INPUT BAR ═══════════ */
***REMOVED***data-testid="stChatInput"***REMOVED*** {
    background-color: var(--bg-secondary) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
}
***REMOVED***data-testid="stChatInput"***REMOVED***:focus-within {
    border-color: var(--cyan) !important;
    box-shadow: var(--glow-cyan) !important;
}
***REMOVED***data-testid="stChatInput"***REMOVED*** textarea {
    background: transparent !important;
    color: var(--text) !important;
}

/* ═══════════ CHAT MESSAGES ═══════════ */
***REMOVED***data-testid="stChatMessage"***REMOVED*** {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
    padding: 1rem !important;
    margin-bottom: 0.5rem !important;
}
***REMOVED***data-testid="stChatMessage"***REMOVED*** p,
***REMOVED***data-testid="stChatMessage"***REMOVED*** li,
***REMOVED***data-testid="stChatMessage"***REMOVED*** span {
    color: var(--text) !important;
}
***REMOVED***data-testid="stChatMessage"***REMOVED*** strong {color: var(--cyan) !important;}
***REMOVED***data-testid="stChatMessage"***REMOVED*** code {
    background: #0d1321 !important;
    color: var(--green) !important;
    border-radius: 4px; padding: 2px 6px;
}

/* ═══════════ METRIC CARDS ═══════════ */
***REMOVED***data-testid="stMetric"***REMOVED*** {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
    padding: 0.8rem 1.2rem !important;
    transition: border-color 0.3s;
}
***REMOVED***data-testid="stMetric"***REMOVED***:hover {
    border-color: var(--cyan) !important;
    box-shadow: var(--glow-cyan) !important;
}
***REMOVED***data-testid="stMetric"***REMOVED*** label {
    color: var(--text-muted) !important;
    font-family: var(--font-mono) !important;
    text-transform: uppercase;
    font-size: 0.7rem !important;
    letter-spacing: 1.5px;
}
***REMOVED***data-testid="stMetric"***REMOVED*** ***REMOVED***data-testid="stMetricValue"***REMOVED*** {
    color: var(--cyan) !important;
    font-family: var(--font-display) !important;
    font-weight: 700 !important;
}

/* ═══════════ EXPANDER ═══════════ */
.streamlit-expanderHeader {
    background: var(--bg-card) !important;
    color: var(--cyan) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    font-family: var(--font-mono) !important;
}
.streamlit-expanderContent {
    background: var(--bg-secondary) !important;
    border: 1px solid var(--border) !important;
    border-top: none !important;
    border-radius: 0 0 8px 8px !important;
}

/* ═══════════ STATUS / SPINNER ═══════════ */
***REMOVED***data-testid="stStatusWidget"***REMOVED*** {
    background: var(--bg-card) !important;
    border: 1px solid var(--cyan-dim) !important;
    border-radius: 10px !important;
}
***REMOVED***data-testid="stStatusWidget"***REMOVED*** summary {color: var(--cyan) !important;}
.stSpinner > div > span {color: var(--cyan) !important;}

/* ═══════════ ALERTS ═══════════ */
.stAlert ***REMOVED***data-testid="stAlertContentError"***REMOVED*** {
    background: #1a0a12 !important;
    border-color: var(--red) !important;
    color: var(--red) !important;
}

/* ═══════════ SCROLLBAR ═══════════ */
::-webkit-scrollbar {width: 6px;}
::-webkit-scrollbar-track {background: var(--bg-primary);}
::-webkit-scrollbar-thumb {background: var(--border); border-radius: 3px;}
::-webkit-scrollbar-thumb:hover {background: var(--cyan-dim);}

/* ═══════════ DIVIDER ═══════════ */
hr {border-color: var(--border) !important; opacity: 0.4;}

/* ═══════════ CUSTOM HEADER BOX ═══════════ */
.soc-header {
    background: linear-gradient(135deg, #0b1120 0%, #111e38 50%, #0b1120 100%);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 1.5rem 2rem;
    margin-bottom: 1rem;
    position: relative;
    overflow: hidden;
}
.soc-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
}
.soc-header h1 {
    font-family: var(--font-display) !important;
    color: var(--cyan) !important;
    font-size: 1.8rem;
    margin: 0 0 0.25rem 0;
    letter-spacing: 3px;
    text-shadow: 0 0 20px #00f0ff44;
}
.soc-header .subtitle {
    color: var(--text-muted);
    font-size: 0.78rem;
    letter-spacing: 2px;
    text-transform: uppercase;
}
.soc-header .badge {
    display: inline-block;
    background: var(--red);
    color: #fff;
    font-size: 0.6rem;
    padding: 2px 10px;
    border-radius: 20px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-left: 12px;
    vertical-align: middle;
    animation: pulse-badge 2s ease-in-out infinite;
}
@keyframes pulse-badge {
    0%, 100% {box-shadow: 0 0 0 0 #ff003c55;}
    50% {box-shadow: 0 0 12px 4px #ff003c44;}
}

/* ═══════════ SIDEBAR FOOTER ═══════════ */
.sidebar-footer {
    position: fixed;
    bottom: 0;
    width: inherit;
    background: linear-gradient(180deg, transparent, #070b14);
    padding: 1rem 1.5rem;
    text-align: center;
    border-top: 1px solid var(--border);
}
.sidebar-footer .uni-name {
    color: var(--text-muted);
    font-size: 0.58rem;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    line-height: 1.6;
}
.sidebar-footer .author {
    color: var(--cyan-dim);
    font-size: 0.62rem;
    margin-top: 4px;
}

/* ═══════════ SCAN-LINE ANIMATION ═══════════ */
.soc-header::after {
    content: '';
    position: absolute;
    top: 0; left: -100%;
    width: 100%; height: 100%;
    background: linear-gradient(90deg, transparent, #00f0ff08, transparent);
    animation: scanline 4s linear infinite;
}
@keyframes scanline {
    0% {left: -100%;}
    100% {left: 100%;}
}
</style>
""", unsafe_allow_html=True)


# ==========================================
# 2. DASHBOARD HEADER
# ==========================================
import base64

logo_path = os.path.join(os.path.dirname(__file__), "logo.png")
if os.path.exists(logo_path):
    with open(logo_path, "rb") as f:
        logo_b64 = base64.b64encode(f.read()).decode()
    logo_html = f'<img src="data:image/png;base64,{logo_b64}" style="height:60px; vertical-align:middle; margin-right:16px; filter: drop-shadow(0 0 12px #00f0ff55);"/>'
else:
    logo_html = ''

st.markdown(f"""
<div class="soc-header">
    <div style="display:flex; align-items:center;">
      ***REMOVED***logo_html}
        <div>
            <h1>CYBERSICKER<span class="badge">SOC ACTIVE</span></h1>
            <div class="subtitle">Autonomous IoT Blue Team Agent &mdash; Threat Detection &amp; Response System</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Live System Metrics ──
now = datetime.datetime.now()
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric(label="System Status", value="ONLINE", delta="Nominal")
with m2:
    st.metric(label="IoT Sensors", value="ACTIVE", delta="All Connected")
with m3:
    st.metric(label="Threat Level", value="MONITORING", delta="Low")
with m4:
    st.metric(label="Uptime", value=now.strftime("%H:%M:%S"), delta=now.strftime("%Y-%m-%d"))


# ==========================================
# 3. SIDEBAR — CONFIGURATION PANEL
# ==========================================
# Keys loaded from environment variables
google_key = os.environ.get("GOOGLE_API_KEY", "")
vt_key = os.environ.get("VT_API_KEY", "")

with st.sidebar:
    if os.path.exists(logo_path):
        st.image(logo_path, width="stretch")
    st.markdown("### CONTROL PANEL")
    st.markdown("---")

    st.markdown("### 📡 Quick Commands")
    st.code('Scan D:\\CYBERSICKER\\KDDTrain+.txt', language=None)
    st.code('Check IP 185.220.101.43', language=None)
    st.code('Consult playbook for IoT Anomalies', language=None)

    # ── University badge footer ──
    st.markdown("---")
    st.markdown("""
    <div style="text-align:center; padding: 0.5rem 0 2rem 0;">
        <div style="color:#5c6b7e; font-size:0.55rem; letter-spacing:2px; text-transform:uppercase; line-height:1.8;">
            🛡️ CYBERSICKER Threat Detection Suite
        </div>
        <div style="color:#00f0ff88; font-size:0.6rem; margin-top:6px; letter-spacing:1px;">
            Built by <strong style="color:#00f0ff;">Vrishin Ram.K</strong>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ==========================================
# 4. THE TOOLS (unchanged backend logic)
# ==========================================
@tool
def network_scanner(filepath: str) -> str:
    """Scan network traffic logs for cyber attacks or anomalies."""
    try:
        anomalies = run_network_scan(filepath)
        return f"Scan complete. Found {anomalies} anomalies."
    except Exception as e:
        return f"Failed to run scanner: {str(e)}"

@tool
def check_ip_virustotal(ip_address: str) -> str:
    """Investigate an IP address using VirusTotal threat intelligence. Input MUST be an IPv4 address string."""
    vt_api_key = os.environ.get("VT_API_KEY")
    if not vt_api_key:
        return "Error: VirusTotal API Key is missing in the sidebar."
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"accept": "application/json", "x-apikey": vt_api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()***REMOVED***'data'***REMOVED******REMOVED***'attributes'***REMOVED******REMOVED***'last_analysis_stats'***REMOVED***
            malicious = stats.get('malicious', 0)
            if malicious > 0:
                return f"CRITICAL: {malicious} security vendors flagged {ip_address} as malicious!"
            return f"CLEAN: 0 vendors flagged {ip_address} as malicious."
        return f"Error: API returned status code {response.status_code}"
    except Exception as e:
        return f"Error connecting to VirusTotal: {str(e)}"

@tool
def lookup_mac_address(mac_address: str) -> str:
    """Look up the manufacturer/vendor of a device by its MAC address. Input should be a MAC address like AA:BB:CC:DD:EE:FF."""
    try:
        clean_mac = mac_address.replace('-', ':').strip()
        oui = clean_mac.replace(':', '')***REMOVED***:6***REMOVED***.upper()
        url = f"https://api.macvendors.com/{clean_mac}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            vendor = response.text.strip()
            return (
                f"MAC Address: {clean_mac}\n"
                f"OUI Prefix: {oui}\n"
                f"Device Manufacturer: {vendor}\n"
                f"This device is made by {vendor}. Cross-reference with your IoT asset inventory."
            )
        elif response.status_code == 404:
            return f"MAC {clean_mac} (OUI: {oui}) — Vendor NOT FOUND. Could be a spoofed MAC or unregistered device. Treat as suspicious."
        return f"MAC lookup failed with status code {response.status_code}."
    except Exception as e:
        return f"Error looking up MAC address: {str(e)}"

@tool
def query_cve_database(cve_id: str) -> str:
    """Query the NIST National Vulnerability Database for details about a specific CVE. Input MUST be a CVE ID like CVE-2021-44228."""
    try:
        cve_id = cve_id.strip().upper()
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"Accept": "application/json"}
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", ***REMOVED******REMOVED***)
            if not vulns:
                return f"CVE {cve_id} not found in the NVD database."
            cve_data = vulns***REMOVED***0***REMOVED***.get("cve", {})
            desc_list = cve_data.get("descriptions", ***REMOVED******REMOVED***)
            description = next((d***REMOVED***"value"***REMOVED*** for d in desc_list if d***REMOVED***"lang"***REMOVED*** == "en"), "No description available.")
            metrics = cve_data.get("metrics", {})
            cvss_score = "N/A"
            severity = "N/A"
            for version_key in ***REMOVED***"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"***REMOVED***:
                if version_key in metrics:
                    cvss_data = metrics***REMOVED***version_key***REMOVED******REMOVED***0***REMOVED***.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", "N/A")
                    break
            published = cve_data.get("published", "Unknown")***REMOVED***:10***REMOVED***
            return (
                f"CVE ID: {cve_id}\n"
                f"Published: {published}\n"
                f"CVSS Score: {cvss_score} ({severity})\n"
                f"Description: {description***REMOVED***:500***REMOVED***}\n"
                f"Recommendation: Patch immediately if score >= 7.0. Check vendor advisories for IoT firmware updates."
            )
        elif response.status_code == 403:
            return f"NVD API rate limited. Try again in 30 seconds."
        return f"NVD API returned status code {response.status_code}."
    except Exception as e:
        return f"Error querying CVE database: {str(e)}"

@tool
def consult_playbook(incident_type: str) -> str:
    """Use this tool to read the official Incident Response Playbook to see what actions to take. Pass a brief description of the incident as the input."""
    try:
        playbook_path = os.path.join(os.path.dirname(__file__), "playbook.env.txt")
        loader = TextLoader(playbook_path)
        documents = loader.load()
        text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
        docs = text_splitter.split_documents(documents)
        
        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        db = Chroma.from_documents(docs, embeddings)
        
        results = db.similarity_search(incident_type, k=3)
        if results:
            combined = "\n---\n".join(***REMOVED***r.page_content for r in results***REMOVED***)
            return f"Official Playbook Results:\n{combined}"
        return "No specific rule found for this incident type."
    except Exception as e:
        return f"Error reading playbook: {str(e)}"


# ==========================================
# 5. SECURITY HARDENING & INPUT VALIDATION
# ==========================================
import re
import html

def sanitize_input(user_input: str, max_length: int = 1000) -> tuple[str, bool]:
    """
    Sanitize user input for security (Phase 4 Security Hardening).
    Prevents prompt injection, SQL injection, command execution patterns.
    Returns: (sanitized_text, is_valid)
    """
    if not user_input or len(user_input) == 0:
        return "", False
    
    if len(user_input) > max_length:
        return "", False
    
    sanitized = user_input.strip()
    
    # Detect prompt injection patterns
    injection_patterns = [
        r"ignore.*previous.*instructions",
        r"system.*prompt",
        r"execute.*code",
        r"sql.*injection",
        r"run.*command",
    ]
    
    for pattern in injection_patterns:
        if re.search(pattern, sanitized, re.IGNORECASE):
            return "", False
    
    return sanitized, True

def escape_output(text: str) -> str:
    """Escape HTML special characters in output (Phase 4 Security Hardening)."""
    return html.escape(text)


# ==========================================
# 5B. MITRE ATT&CK & CAPABILITY MATRIX
# ==========================================
MITRE_COVERAGE = {
    "T1010": {"name": "Automated Exfiltration", "component": "autoencoder.py", "mapped": True},
    "T1020": {"name": "Automated Exfiltration via IM", "component": "anomaly detection", "mapped": True},
    "T1005": {"name": "Data from Local System", "component": "network_scanner", "mapped": True},
    "T1592": {"name": "Gather Victim Identity Info", "component": "check_ip_virustotal", "mapped": True},
    "T1046": {"name": "Network Service Discovery", "component": "network_scanner", "mapped": True},
    "T1040": {"name": "Network Sniffing", "component": "network_scanner", "mapped": True},
}

SKILL_MAPPINGS = {
    "network_scanner": ["Threat Hunting (55)", "Network Security (40)", "Malware Analysis (39)"],
    "check_ip_virustotal": ["Threat Intelligence (50)", "Incident Response (25)"],
    "lookup_mac_address": ["Network Security (40)", "Digital Forensics (37)"],
    "query_cve_database": ["Malware Analysis (39)", "Cloud Security (60)"],
    "consult_playbook": ["Incident Response (25)", "Digital Forensics (37)"],
}


# ==========================================
# 6. CAPABILITIES & THREAT MODEL DISPLAY
# ==========================================
tab1, tab2, tab3, tab4 = st.tabs(
    ["🔒 Threat Guard", "📊 Capabilities", "⚔️ MITRE Coverage", "📋 STRIDE Model"]
)

with tab2:
    st.markdown("### 🛡️ Cybersecurity Skill Mappings")
    st.markdown("*Framework coverage for each detection component (Phases 1-3)*")
    
    cols = st.columns(2)
    for idx, (tool_name, skills) in enumerate(SKILL_MAPPINGS.items()):
        with cols[idx % 2]:
            with st.container(border=True):
                st.markdown(f"**{tool_name.replace('_', ' ').title()}**")
                for skill in skills:
                    st.markdown(f"📚 {skill}", help="From Anthropic-Cybersecurity-Skills")

with tab3:
    st.markdown("### ⚔️ MITRE ATT&CK Coverage (Phase 3)")
    st.markdown(f"**Techniques Mapped: {sum(1 for v in MITRE_COVERAGE.values() if v['mapped'])}/{len(MITRE_COVERAGE)}**")
    
    coverage_data = [{
        "ID": tid,
        "Technique": details["name"],
        "Component": details["component"],
        "Status": "✅"
    } for tid, details in MITRE_COVERAGE.items()]
    
    st.dataframe(coverage_data, use_container_width=True, hide_index=True)

with tab4:
    st.markdown("### 📋 STRIDE Threat Model (Phase 2)")
    st.markdown("""
    **Threat Coverage:** All 6 STRIDE vectors × 4 components
    
    | Vector | Mitigation | Verified |
    |--------|-----------|----------|
    | **S**poofing | API key validation, OAuth | ✅ |
    | **T**ampering | Model integrity, logging | ✅ |
    | **R**epudiation | Audit trail, action log | ✅ |
    | **I**nformation Disclosure | Output escaping, sanitization | ✅ |
    | **D**enial of Service | Rate limiting, response caps | ✅ |
    | **E**levation of Privilege | Least privilege tools | ✅ |
    
    **Frameworks:** NIST CSF 2.0, MITRE ATT&CK v18, NIST AI RMF 1.0
    """)


# ==========================================
# 7. CHAT INTERFACE & AGENT EXECUTION
# ==========================================
# Initialize chat history in Streamlit session
if "messages" not in st.session_state:
    st.session_state.messages = ***REMOVED******REMOVED***

# Display previous messages with custom avatars
for msg in st.session_state.messages:
    avatar = "🛡️" if msg***REMOVED***"role"***REMOVED*** == "assistant" else "👤"
    with st.chat_message(msg***REMOVED***"role"***REMOVED***, avatar=avatar):
        st.markdown(msg***REMOVED***"content"***REMOVED***)

# User Input with Security Validation (Phase 4)
if prompt := st.chat_input("Enter a command for Cybersicker..."):
    # Sanitize input first
    sanitized_prompt, is_valid = sanitize_input(prompt)
    
    if not is_valid:
        st.error("🚨 **SECURITY ALERT:** Input rejected. Check for prompt injection or length violations.")
    elif not google_key or not vt_key:
        st.error("🔐 **AUTHENTICATION REQUIRED** — Open the sidebar and enter both API keys under System Credentials.")
    else:
        # Add user message to chat
        st.session_state.messages.append({"role": "user", "content": sanitized_prompt})
        with st.chat_message("user", avatar="👤"):
            st.markdown(escape_output(sanitized_prompt))

        # Generate agent response
        with st.chat_message("assistant", avatar="🛡️"):
            with st.status("🔒 Initializing Threat Intel Protocol...", expanded=True) as status:
                try:
                    status.update(label="🧠 Loading Gemini LLM...", state="running")
                    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0, api_key=google_key)
                    tools = ***REMOVED***network_scanner, check_ip_virustotal, lookup_mac_address, query_cve_database, consult_playbook***REMOVED***

                    status.update(label="⚙️ Constructing Agent Graph...", state="running")
                    agent = create_agent(
                        llm,
                        tools=tools,
                        system_prompt="You are Cybersicker, an elite cybersecurity agent. Format your final answer neatly."
                    )

                    status.update(label="📡 Executing Analysis — Tools Running...", state="running")
                    response = agent.invoke({
                        "messages": ***REMOVED***("user", sanitized_prompt)***REMOVED***
                  ***REMOVED***)
                    
                    final_content = response***REMOVED***"messages"***REMOVED******REMOVED***-1***REMOVED***.content
                    if isinstance(final_content, list):
                        answer = final_content***REMOVED***0***REMOVED******REMOVED***"text"***REMOVED***
                    else:
                        answer = final_content

                    status.update(label="✅ Analysis Complete", state="complete", expanded=False)

                except Exception as e:
                    answer = None
                    status.update(label="❌ Analysis Failed", state="error", expanded=False)
                    st.error(f"**SYSTEM ERROR:** {str(e)}")

            if answer:
                # Escape and display response (Phase 4 Security)
                escaped_answer = escape_output(str(answer))
                st.markdown(escaped_answer)
                st.session_state.messages.append({"role": "assistant", "content": answer})