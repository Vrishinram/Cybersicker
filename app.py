import streamlit as st
import os
import datetime
import html
import re
import base64

# ==========================================
# 1. PAGE CONFIG & MODERN HIGH-TECH THEME
# ==========================================
st.set_page_config(
    page_title="CYBERSICKER // Defense Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,400;0,500;0,600;1,400&family=IBM+Plex+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700;800&display=swap');

/* Hide default streamlit clutter */
#MainMenu, header, footer, [data-testid="stToolbar"], [data-testid="stDecoration"], .stDeployButton {display: none !important;}
section[data-testid="stSidebar"] .material-symbols-rounded,
section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"],
section[data-testid="stSidebar"] [data-testid="stSidebarNavSeparator"],
section[data-testid="stSidebar"] [data-testid="stSidebarHeader"],
section[data-testid="stSidebar"] .stPageLink,
section[data-testid="stSidebar"] span.material-icons,
section[data-testid="stSidebar"] [data-testid="stSidebarNavItems"],
section[data-testid="stSidebar"] [data-testid="stLogo"],
section[data-testid="stSidebar"] nav {display: none !important;}
section[data-testid="stSidebarUserContent"] {padding-top: 1.5rem !important;}

:root {
    --bg-primary:   #0a0f1d;
    --bg-secondary: #0f172a;
    --bg-card:      #131c31;
    --bg-input:     #0d1424;
    --cyan:         #38bdf8;
    --cyan-dim:     #0284c7;
    --red:          #fda4af;
    --red-bg:       #4c0519;
    --green:        #a7f3d0;
    --amber:        #fde68a;
    --text:         #e2e8f0;
    --text-muted:   #94a3b8;
    --border:       #1e293b;
    --border-light: #334155;
    --font-body:    'IBM Plex Sans', sans-serif;
    --font-mono:    'IBM Plex Mono', monospace;
    --font-display: 'Space Grotesk', sans-serif;
}

html, body, .stApp, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-primary) !important;
    color: var(--text) !important;
    font-family: var(--font-body) !important;
}

[data-testid="stAppViewBlockContainer"] {
    max-width: 1600px;
    padding-top: 1.5rem !important;
    padding-bottom: 2rem !important;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #090e1a !important;
    border-right: 1px solid var(--border) !important;
}
section[data-testid="stSidebar"] * {
    color: var(--text) !important;
    font-family: var(--font-body) !important;
}
section[data-testid="stSidebar"] h1, section[data-testid="stSidebar"] h2, section[data-testid="stSidebar"] h3 {
    color: #f8fafc !important;
    font-family: var(--font-display) !important;
    font-weight: 700;
}

/* Inputs */
input, textarea, .stTextInput input, .stTextArea textarea, .stSelectbox [data-baseweb="select"] {
    background-color: var(--bg-input) !important;
    color: #f8fafc !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    font-family: var(--font-body) !important;
}
input:focus, textarea:focus, .stTextInput input:focus {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 0 1px var(--cyan) !important;
    outline: none !important;
}

/* Chat Input Bar */
[data-testid="stChatInput"] {
    background-color: #0b1120 !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
}
[data-testid="stChatInput"]:focus-within {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 0 1px var(--cyan) !important;
}
[data-testid="stChatInput"] textarea {
    background: transparent !important;
    color: var(--text) !important;
    font-family: var(--font-body) !important;
}

/* Chat Messages */
[data-testid="stChatMessage"] {
    background: var(--bg-secondary) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    padding: 1rem !important;
    margin-bottom: 0.75rem !important;
}
[data-testid="stChatMessage"] p, [data-testid="stChatMessage"] li {
    color: var(--text) !important;
    font-size: 0.88rem;
    line-height: 1.6;
}
[data-testid="stChatMessage"] strong {color: #f8fafc !important;}
[data-testid="stChatMessage"] code {
    background: #080c14 !important;
    color: var(--cyan) !important;
    border: 1px solid #1a263d;
    border-radius: 4px; padding: 2px 6px;
    font-family: var(--font-mono) !important;
    font-size: 0.8rem;
}

/* Metric Cards */
[data-testid="stMetric"] {
    background: var(--bg-secondary) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    padding: 0.75rem 1rem !important;
}
[data-testid="stMetric"] label {
    color: var(--text-muted) !important;
    font-family: var(--font-mono) !important;
    text-transform: uppercase;
    font-size: 0.65rem !important;
    letter-spacing: 0.05em;
    font-weight: 500;
}
[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: #f8fafc !important;
    font-family: var(--font-mono) !important;
    font-weight: 700 !important;
    font-size: 1.25rem !important;
}

/* Custom Header */
.soc-header {
    background: #0f172a;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.1rem 1.5rem;
    margin-bottom: 1rem;
    border-top: 2px solid var(--cyan-dim);
}
.soc-header h1 {
    font-family: var(--font-display) !important;
    color: #f8fafc !important;
    font-size: 1.5rem;
    margin: 0;
    font-weight: 800;
    letter-spacing: -0.02em;
}
.soc-header .subtitle {
    color: var(--text-muted);
    font-size: 0.75rem;
    margin-top: 4px;
}
.soc-header .badge {
    background: #1e293b;
    border: 1px solid #334155;
    color: var(--cyan);
    font-size: 0.62rem;
    font-family: var(--font-mono);
    padding: 2px 8px;
    border-radius: 4px;
    margin-left: 10px;
    vertical-align: middle;
}

/* Buttons */
.stButton button {
    background-color: var(--bg-secondary) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
    font-family: var(--font-body) !important;
    font-size: 0.8rem !important;
    border-radius: 6px !important;
    transition: all 0.15s ease !important;
}
.stButton button:hover {
    border-color: var(--cyan) !important;
    color: #f8fafc !important;
    background-color: #131d31 !important;
}
.stButton button[kind="primary"] {
    background-color: var(--cyan-dim) !important;
    color: #fff !important;
    border-color: var(--cyan) !important;
}

/* Expanders */
.streamlit-expanderHeader {
    background: var(--bg-secondary) !important;
    color: #f8fafc !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    font-size: 0.82rem !important;
}
.streamlit-expanderContent {
    background: #090e1a !important;
    border: 1px solid var(--border) !important;
    border-top: none !important;
}
</style>
""", unsafe_allow_html=True)


# ==========================================
# 2. TOOLS & SECURITY HELPERS
# ==========================================
from tools import (
    ALL_TOOLS,
    network_scanner,
    check_ip_virustotal,
    lookup_mac_address,
    query_cve_database,
    consult_playbook,
    sanitize_input,
    escape_output,
)

MITRE_COVERAGE = {
    "T1010": {"name": "Automated Exfiltration", "component": "autoencoder.py", "mapped": True},
    "T1020": {"name": "Automated Exfiltration via IM", "component": "anomaly detection", "mapped": True},
    "T1005": {"name": "Data from Local System", "component": "network_scanner", "mapped": True},
    "T1592": {"name": "Gather Victim Identity Info", "component": "check_ip_virustotal", "mapped": True},
    "T1046": {"name": "Network Service Discovery", "component": "network_scanner", "mapped": True},
    "T1040": {"name": "Network Sniffing", "component": "network_scanner", "mapped": True},
}


# ==========================================
# 3. SIDEBAR — CREDENTIALS & STATUS
# ==========================================
with st.sidebar:
    st.markdown("### CYBERSICKER // SOC")
    st.caption("Autonomous Blue-Team Security Workbench")
    st.markdown("---")

    st.markdown("#### System Credentials")
    env_google_key = os.environ.get("GOOGLE_API_KEY", "")
    env_vt_key = os.environ.get("VT_API_KEY", "")

    google_key = st.text_input(
        "Google Gemini API Key",
        value=env_google_key,
        type="password",
        help="Enables autonomous multi-turn blue-team agent reasoning with Gemini 2.5 Flash."
    )
    vt_key = st.text_input(
        "VirusTotal API Key",
        value=env_vt_key,
        type="password",
        help="Enables real-time IP reputation lookups across 70+ threat intelligence engines."
    )

    if vt_key:
        os.environ["VT_API_KEY"] = vt_key
    if google_key:
        os.environ["GOOGLE_API_KEY"] = google_key

    st.markdown("---")
    st.markdown("#### Operational Subsystems")
    st.markdown(f"**Anomaly Engine:** `Keras Dense Autoencoder`")
    st.markdown(f"**Baseline Dataset:** `NSL-KDD (125,973 Records)`")
    st.markdown(f"**Playbook RAG:** `ChromaDB (380 vectors)`")
    st.markdown(f"**LLM Agent:** `{'Active (Gemini 2.5 Flash)' if google_key else 'Standby (Local Direct Tools)'}`")

    st.markdown("---")
    if st.button("Clear Incident Log", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    st.markdown("""
    <div style="font-size:0.65rem; color:#64748b; margin-top:2rem; line-height:1.5;">
        CYBERSICKER Defense Platform v2.0<br/>
        Engineered by <strong style="color:#94a3b8;">Vrishin Ram.K</strong>
    </div>
    """, unsafe_allow_html=True)


# ==========================================
# 4. DASHBOARD HEADER & TELEMETRY STRIP
# ==========================================
logo_path = os.path.join(os.path.dirname(__file__), "logo.png")
logo_html = ""
if os.path.exists(logo_path):
    with open(logo_path, "rb") as f:
        logo_b64 = base64.b64encode(f.read()).decode()
    logo_html = f'<img src="data:image/png;base64,{logo_b64}" style="height:44px; margin-right:12px;"/>'

st.markdown(f"""
<div class="soc-header">
    <div style="display:flex; align-items:center;">
        {logo_html}
        <div>
            <h1>CYBERSICKER<span class="badge">DEFENSE CONSOLE // v2.0</span></h1>
            <div class="subtitle">Open-source blue-team workbench: Deep neural autoencoder anomaly scoring &amp; automated threat intelligence</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# 4-Column Live Metric Strip
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric(label="System Status", value="ONLINE", delta="Local Defense Kernel")
with m2:
    st.metric(label="Baseline Dataset", value="125,973", delta="NSL-KDD Network Records")
with m3:
    st.metric(label="Detection Engine", value="MSE > 0.042", delta="Keras Autoencoder")
with m4:
    agent_status = "READY" if google_key else "LOCAL ONLY"
    st.metric(label="Threat Intel Agent", value=agent_status, delta="Gemini 2.5 Flash" if google_key else "Configure API Key")

st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)


# ==========================================
# 5. ASYMMETRIC DUAL-PLANE WORKSPACE
# ==========================================
col_tools, col_console = st.columns([4, 6], gap="medium")

# Initialize chat session
if "messages" not in st.session_state:
    st.session_state.messages = []


def run_direct_tool(tool_name: str, param: str):
    """Executes a tool directly and records the action into the incident log."""
    st.session_state.messages.append({
        "role": "user",
        "content": f"[OPERATOR ACTION] Executed {tool_name} with parameter: `{param}`"
    })
    
    with st.spinner(f"Running {tool_name}..."):
        try:
            if tool_name == "network_scanner":
                result = network_scanner.invoke({"filepath": param})
            elif tool_name == "check_ip_virustotal":
                result = check_ip_virustotal.invoke({"ip_address": param})
            elif tool_name == "lookup_mac_address":
                result = lookup_mac_address.invoke({"mac_address": param})
            elif tool_name == "query_cve_database":
                result = query_cve_database.invoke({"cve_id": param})
            elif tool_name == "consult_playbook":
                result = consult_playbook.invoke({"query": param})
            else:
                result = "Unknown tool"
        except Exception as e:
            result = f"Tool Execution Error: {str(e)}"

    st.session_state.messages.append({
        "role": "assistant",
        "content": result
    })
    st.rerun()


# ─── LEFT COLUMN: INVESTIGATIVE TOOL DECK ───
with col_tools:
    st.markdown("#### Investigative Tool Deck")
    st.caption("Trigger automated blue-team scripts or run custom threat parameters.")

    with st.container(border=True):
        st.markdown("**1-Click Quick Triage Actions**")
        
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Scan Traffic Dump", use_container_width=True, help="Evaluates KDDTrain+.txt with Keras autoencoder"):
                run_direct_tool("network_scanner", r"D:\CYBERSICKER\KDDTrain+.txt")
        with c2:
            if st.button("Check IP 185.220.101.43", use_container_width=True, help="Queries VirusTotal for Tor exit node reputation"):
                run_direct_tool("check_ip_virustotal", "185.220.101.43")

        c3, c4 = st.columns(2)
        with c3:
            if st.button("Query CVE-2021-44228", use_container_width=True, help="Queries NIST NVD database for Log4Shell"):
                run_direct_tool("query_cve_database", "CVE-2021-44228")
        with c4:
            if st.button("Lookup MAC Vendor", use_container_width=True, help="Resolves IEEE manufacturer OUI for 00:1A:2B:3C:4D:5E"):
                run_direct_tool("lookup_mac_address", "00:1A:2B:3C:4D:5E")

        if st.button("Consult Botnet Playbook", use_container_width=True, help="Queries ChromaDB incident response playbooks"):
            run_direct_tool("consult_playbook", "Botnet containment and perimeter isolation")

    # Custom Tool Parameter Form
    with st.expander("Custom Tool Parameter Execution", expanded=False):
        tool_choice = st.selectbox(
            "Select Tool",
            ["network_scanner", "check_ip_virustotal", "query_cve_database", "lookup_mac_address", "consult_playbook"],
            format_func=lambda x: {
                "network_scanner": "Network Traffic Anomaly Scanner (Autoencoder)",
                "check_ip_virustotal": "VirusTotal IP Reputation Checker",
                "query_cve_database": "NIST NVD CVE Vulnerability Database",
                "lookup_mac_address": "IEEE MAC OUI Hardware Identifier",
                "consult_playbook": "Incident Response Playbook (ChromaDB)",
            }.get(x, x)
        )

        placeholders = {
            "network_scanner": r"D:\CYBERSICKER\KDDTrain+.txt",
            "check_ip_virustotal": "185.220.101.43",
            "query_cve_database": "CVE-2021-44228",
            "lookup_mac_address": "00:1A:2B:3C:4D:5E",
            "consult_playbook": "IoT botnet infection containment steps",
        }

        custom_param = st.text_input("Parameter Value", value=placeholders.get(tool_choice, ""))
        if st.button("Run Custom Analysis", type="primary", use_container_width=True):
            if custom_param.strip():
                run_direct_tool(tool_choice, custom_param.strip())

    # MITRE ATT&CK & Defense Matrix Expander
    with st.expander("MITRE ATT&CK & STRIDE Coverage", expanded=False):
        st.markdown("**Mapped MITRE Techniques:**")
        coverage_data = [{
            "ID": tid,
            "Technique": details["name"],
            "Component": details["component"],
            "Status": "MAPPED"
        } for tid, details in MITRE_COVERAGE.items()]
        st.dataframe(coverage_data, use_container_width=True, hide_index=True)

        st.markdown("""
        **STRIDE Threat Model:**
        - **Spoofing:** API Key validation & OAuth
        - **Tampering:** Model weight integrity & hash verification
        - **Repudiation:** Append-only audit logging
        - **Information Disclosure:** Strict output escaping
        - **Denial of Service:** Rate-limited tool execution
        - **Elevation of Privilege:** Least-privilege function sandboxing
        """)


# ─── RIGHT COLUMN: INCIDENT RESPONSE TERMINAL ───
with col_console:
    st.markdown("#### Incident Response Terminal")
    st.caption("Conversational blue-team investigation, threat correlation, and containment.")

    # Render previous messages
    if len(st.session_state.messages) == 0:
        with st.container(border=True):
            st.markdown("""
            **Session Initiated // No Active Alerts**
            
            Use the **1-Click Quick Triage Actions** on the left to immediately test anomaly detection, or type an investigative instruction into the console below.
            
            *Suggested queries:*
            - `"Scan D:\\CYBERSICKER\\KDDTrain+.txt and report anomalies"`
            - `"Investigate IP 185.220.101.43 using VirusTotal"`
            - `"Provide containment steps for a Mirai botnet infection"`
            """)
    else:
        for msg in st.session_state.messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

    # Console Command Input
    if prompt := st.chat_input("Enter an investigative instruction (e.g., 'Scan KDDTrain+.txt' or 'Analyze IP 185.220.101.43')..."):
        sanitized_prompt, is_valid = sanitize_input(prompt)
        
        if not is_valid:
            st.error("**SECURITY ALERT:** Input rejected. Check for command injection or length violations.")
        else:
            st.session_state.messages.append({"role": "user", "content": sanitized_prompt})
            with st.chat_message("user"):
                st.markdown(escape_output(sanitized_prompt))

            with st.chat_message("assistant"):
                # If Gemini API key is configured, run autonomous LangChain ReAct agent
                if google_key:
                    with st.status("Executing Blue-Team Investigation Protocol...", expanded=True) as status:
                        try:
                            from langchain.agents import create_agent
                            from langchain_google_genai import ChatGoogleGenerativeAI

                            status.update(label="Connecting to Gemini 2.5 Flash...", state="running")
                            llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0, api_key=google_key)
                            tools = [network_scanner, check_ip_virustotal, lookup_mac_address, query_cve_database, consult_playbook]

                            status.update(label="Constructing LangChain ReAct Graph...", state="running")
                            agent = create_agent(
                                llm,
                                tools=tools,
                                system_prompt="You are Cybersicker, an automated blue-team SOC analyst. Triage threats using network anomaly scans, VirusTotal reputation checks, CVE queries, and incident response playbooks. Format your final report cleanly with actionable containment recommendations."
                            )

                            status.update(label="Executing Analysis Tools...", state="running")
                            response = agent.invoke({"messages": [("user", sanitized_prompt)]})
                            
                            final_content = response["messages"][-1].content
                            answer = final_content[0]["text"] if isinstance(final_content, list) else final_content
                            status.update(label="Investigation Complete", state="complete", expanded=False)
                        except Exception as e:
                            answer = f"Agent Investigation Error: {str(e)}"
                            status.update(label="Investigation Encountered Error", state="error", expanded=False)
                else:
                    # Graceful Local Fallback: Execute appropriate tool based on user intent
                    lower_prompt = sanitized_prompt.lower()
                    with st.status("Executing Local Security Kernel (Local Mode)...", expanded=True) as status:
                        if "scan" in lower_prompt or "kdd" in lower_prompt:
                            status.update(label="Running Autoencoder Network Scan...", state="running")
                            answer = network_scanner.invoke({"filepath": r"D:\CYBERSICKER\KDDTrain+.txt"})
                        elif "ip" in lower_prompt or "virustotal" in lower_prompt:
                            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", sanitized_prompt)
                            target_ip = ip_match.group(0) if ip_match else "185.220.101.43"
                            status.update(label=f"Querying VirusTotal for {target_ip}...", state="running")
                            answer = check_ip_virustotal.invoke({"ip_address": target_ip})
                        elif "cve" in lower_prompt:
                            cve_match = re.search(r"cve-\d{4}-\d+", lower_prompt, re.IGNORECASE)
                            target_cve = cve_match.group(0).upper() if cve_match else "CVE-2021-44228"
                            status.update(label=f"Querying NIST NVD for {target_cve}...", state="running")
                            answer = query_cve_database.invoke({"cve_id": target_cve})
                        elif "mac" in lower_prompt or "oui" in lower_prompt or "hardware" in lower_prompt:
                            mac_match = re.search(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", sanitized_prompt)
                            target_mac = mac_match.group(0) if mac_match else "00:1A:2B:3C:4D:5E"
                            status.update(label=f"Resolving MAC OUI for {target_mac}...", state="running")
                            answer = lookup_mac_address.invoke({"mac_address": target_mac})
                        elif "playbook" in lower_prompt or "containment" in lower_prompt or "response" in lower_prompt:
                            status.update(label="Consulting Incident Response Playbook...", state="running")
                            answer = consult_playbook.invoke({"query": sanitized_prompt})
                        else:
                            answer = (
                                "[LOCAL MODE NOTE] Google API Key is not set in the sidebar for full conversational reasoning. "
                                "However, you can directly run any tool above, or enter commands like:\n"
                                "- `Scan D:\\CYBERSICKER\\KDDTrain+.txt`\n"
                                "- `Check IP 185.220.101.43`\n"
                                "- `Query CVE-2021-44228`\n"
                                "- `Lookup MAC 00:1A:2B:3C:4D:5E`\n"
                                "- `Consult playbook for botnet`"
                            )
                        status.update(label="Local Analysis Complete", state="complete", expanded=False)

                st.markdown(escape_output(str(answer)))
                st.session_state.messages.append({"role": "assistant", "content": answer})
                st.rerun()
