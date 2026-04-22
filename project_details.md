# CYBERSICKER — Full Project Documentation

> **Cyberattack Detection System for IoT Environments via Hybrid Intelligence**
> Built by **Vrishin Ram.K**

---

## Project Overview

**CYBERSICKER** is an AI-powered **Security Operations Center (SOC)** platform designed to detect, analyze, and respond to cyber threats targeting **Internet of Things (IoT)** environments. It combines **deep learning anomaly detection** with an **autonomous LLM-powered agent** that can investigate threats using real-world threat intelligence APIs and an internal incident response playbook.

### Core Idea

The system simulates a **blue-team SOC analyst** — it can scan network traffic logs for anomalies using an autoencoder neural network, investigate suspicious IPs via VirusTotal, look up device manufacturers by MAC address, query the NIST CVE database, and consult an internal incident response playbook — all orchestrated autonomously by a Google Gemini LLM agent.

---

## Technology Stack

| Layer | Technology |
|---|---|
| **Frontend / Dashboard** | Streamlit (Python) with custom military-grade dark CSS |
| **LLM Brain** | Google Gemini 2.5 Flash via `langchain_google_genai` |
| **Agent Framework** | LangChain (`create_agent`, `@tool` decorators) |
| **Anomaly Detection ML** | TensorFlow/Keras Autoencoder + Scikit-Learn (PCA, StandardScaler) |
| **Playbook RAG** | LangChain `TextLoader` → `CharacterTextSplitter` → `HuggingFaceEmbeddings` → `ChromaDB` |
| **Threat Intelligence** | VirusTotal API, NIST NVD API, macvendors.com API |
| **Dataset** | KDD Cup 1999 (NSL-KDD) — ***REMOVED***KDDTrain+.txt***REMOVED***(file:///d:/CYBERSICKER/KDDTrain+.txt) |

---

## Architecture

```mermaid
graph TD
    A***REMOVED***"👤 User Input<br/>(Chat or CLI)"***REMOVED*** --> B***REMOVED***"🤖 Gemini 2.5 Flash Agent<br/>(LangChain)"***REMOVED***
    B --> C***REMOVED***"🔍 Network Scanner<br/>(autoencoder.py)"***REMOVED***
    B --> D***REMOVED***"🌐 VirusTotal<br/>IP Reputation Check"***REMOVED***
    B --> E***REMOVED***"📋 Playbook RAG<br/>(ChromaDB)"***REMOVED***
    B --> F***REMOVED***"🔎 CVE Lookup<br/>(NIST NVD API)"***REMOVED***
    B --> G***REMOVED***"📡 MAC Lookup<br/>(macvendors.com)"***REMOVED***
    C --> H***REMOVED***"TensorFlow Autoencoder<br/>+ PCA + StandardScaler"***REMOVED***
    H --> I***REMOVED***"KDDTrain+.txt<br/>(NSL-KDD Dataset)"***REMOVED***
    E --> J***REMOVED***"playbook.env.txt<br/>(IR Playbook v2.0)"***REMOVED***
    B --> K***REMOVED***"📊 Streamlit Dashboard<br/>or CLI Output"***REMOVED***
```

---

## File-by-File Breakdown

### 1. ***REMOVED***app.py***REMOVED***(file:///d:/CYBERSICKER/app.py) — Streamlit SOC Dashboard (542 lines)

The **primary user interface** — a full-featured web dashboard with a cybersecurity aesthetic.

**Key Sections:**

| Section | Lines | Description |
|---|---|---|
| Custom CSS Theme | 26–294 | Military-grade SOC dark theme with JetBrains Mono + Orbitron fonts, cyan/red neon accents, glassmorphism cards, scan-line animations |
| Dashboard Header | 297–332 | Logo display, system title with pulsing "SOC ACTIVE" badge, 4 live metric cards (Status, Sensors, Threat Level, Uptime) |
| Sidebar Control Panel | 335–365 | Quick command examples, university branding footer |
| Tool Definitions | 368–481 | 5 LangChain `@tool` functions (see Tools section below) |
| Chat Interface | 484–542 | Streamlit chat UI with session state history, agent invocation with status spinner |

**UI Features:**
- Dark cybersecurity theme with CSS variables (`--cyan`, `--red`, `--green`)
- Google Fonts: **Orbitron** (display) + **JetBrains Mono** (code)
- Animated scan-line effect on header
- Pulsing red "SOC ACTIVE" badge
- Custom scrollbar, metric card hover glow effects
- Chat interface with agent (🛡️) and user (👤) avatars

---

### 2. ***REMOVED***agent.py***REMOVED***(file:///d:/CYBERSICKER/agent.py) — CLI Terminal Agent (121 lines)

A **command-line version** of the agent for direct terminal interaction.

**Key differences from ***REMOVED***app.py***REMOVED***(file:///d:/CYBERSICKER/app.py):**
- Loads API keys from `.env` file with fallback to `getpass` prompt
- Has 3 tools (scanner, VirusTotal, playbook) vs. 5 in the dashboard
- Runs in an interactive `while True` loop
- Prints output directly to terminal with "SOC Report" formatting

---

### 3. ***REMOVED***autoencoder.py***REMOVED***(file:///d:/CYBERSICKER/autoencoder.py) — ML Anomaly Detection Engine (49 lines)

The **core ML component** — a Deep Autoencoder for network traffic anomaly detection.

**Pipeline:**

```
CSV Data → Numeric Column Extraction → StandardScaler → PCA (95% variance)
    → Autoencoder Training → Reconstruction → MSE Calculation → Anomaly Count
```

**Model Architecture:**

| Layer | Neurons | Activation |
|---|---|---|
| Input | `n` (PCA components) | — |
| Encoder 1 | 16 | ReLU |
| Bottleneck | 8 | ReLU |
| Decoder 1 | 16 | ReLU |
| Output | `n` | Linear |

**Key Parameters:**
- **Optimizer:** Adam
- **Loss:** Mean Squared Error (MSE)
- **Epochs:** 5 | **Batch Size:** 256
- **Anomaly Threshold:** MSE > 0.5 (configurable)
- **PCA:** Retains 95% of variance for dimensionality reduction

---

### 4. ***REMOVED***cyber_test.py***REMOVED***(file:///d:/CYBERSICKER/cyber_test.py) — Gemini API Test Script (14 lines)

A simple **test/demo script** that sends a cybersecurity-related prompt to Google Gemini to verify API connectivity.

---

### 5. ***REMOVED***playbook.env.txt***REMOVED***(file:///d:/CYBERSICKER/playbook.env.txt) — Incident Response Playbook (380 lines)

A comprehensive **IoT Incident Response & Threat Detection Playbook** aligned with **NIST CSF 2.0** and **MITRE ATT&CK for ICS/IoT**.

**Contents:**

| Section | Description |
|---|---|
| **SOP-001** | IoT Botnet Infection Response (Mirai, Mozi, etc.) — 4-phase lifecycle |
| **SOP-002** | ICMP Flood / DDoS Mitigation — rate limiting strategy |
| **SOP-003** | IoT Ransomware Containment — "DO NOT PAY" policy |
| **6 General Rules** | Anomaly thresholds, malicious IP blocking, firmware validation, brute-force detection, data exfiltration |
| **MITRE ATT&CK Map** | Top 5 IoT tactics: Default Credentials, C2 Beaconing, Lateral Movement, DoS, Data Exfiltration |
| **NIST Compliance** | VLAN isolation architecture (5 VLANs), inter-VLAN ACL rules, zero-trust baseline |
| **Escalation Matrix** | SEV-1 to SEV-4 response times and handlers |
| **Evidence Preservation** | Chain of custody procedures, PCAP capture, SHA-256 integrity |

---

## Agent Tools (Capabilities)

The LLM agent has access to **5 tools** (in the dashboard; 3 in CLI):

| # | Tool | API Used | Purpose |
|---|---|---|---|
| 1 | ***REMOVED***network_scanner***REMOVED***(file:///d:/CYBERSICKER/app.py#371-379) | Local (autoencoder.py) | Scans CSV/TXT traffic logs using the autoencoder to count anomalies |
| 2 | ***REMOVED***check_ip_virustotal***REMOVED***(file:///d:/CYBERSICKER/agent.py#44-62) | VirusTotal v3 API | Checks if an IP is flagged as malicious by security vendors |
| 3 | ***REMOVED***lookup_mac_address***REMOVED***(file:///d:/CYBERSICKER/app.py#401-422) | macvendors.com | Identifies device manufacturer from MAC address (OUI lookup) |
| 4 | ***REMOVED***query_cve_database***REMOVED***(file:///d:/CYBERSICKER/app.py#423-461) | NIST NVD v2.0 API | Retrieves CVE details including CVSS score and severity |
| 5 | ***REMOVED***consult_playbook***REMOVED***(file:///d:/CYBERSICKER/agent.py#63-82) | Local (ChromaDB RAG) | Semantic search over the IR playbook using embeddings |

---

## How It Works (End-to-End Flow)

1. **User** types a command (e.g., *"Scan D:\CYBERSICKER\KDDTrain+.txt"*)
2. **Streamlit** captures input → passes to **LangChain Agent**
3. **Gemini 2.5 Flash** interprets intent → selects appropriate tool(s)
4. **Tool executes** (e.g., autoencoder scans dataset, VirusTotal checks IP)
5. **Agent** receives tool output → generates a formatted SOC report
6. **Dashboard** displays the response in the chat with status indicators

---

## Dataset — KDDTrain+.txt

The project uses the **NSL-KDD** dataset (***REMOVED***KDDTrain+.txt***REMOVED***(file:///d:/CYBERSICKER/KDDTrain+.txt), ~19 MB), a refined version of the KDD Cup 1999 dataset. It contains labeled network connections with features like:

- Duration, protocol type, service, flag
- Source/destination bytes
- Failed logins, root shell access
- Attack labels: DoS, Probe, R2L, U2R, Normal

---

## Configuration & API Keys

| Key | Source | Purpose |
|---|---|---|
| `GOOGLE_API_KEY` | Environment variable / `.env` | Google Gemini LLM access |
| `VT_API_KEY` | Environment variable / `.env` | VirusTotal threat intelligence |

---

## How to Run

```bash
# Install dependencies
pip install streamlit langchain langchain-google-genai langchain-community chromadb
pip install tensorflow scikit-learn pandas numpy sentence-transformers requests

# Set API keys
set GOOGLE_API_KEY=your_key_here
set VT_API_KEY=your_key_here

# Run the Streamlit dashboard
streamlit run d:\CYBERSICKER\app.py

# Or run the CLI agent
python d:\CYBERSICKER\agent.py
```

---

## Project Summary

> **CYBERSICKER** is a hybrid-intelligence cybersecurity platform that combines a **TensorFlow autoencoder** for anomaly detection with a **Gemini-powered autonomous agent** capable of investigating threats using real-world APIs (VirusTotal, NIST NVD, MAC vendors) and an internal **NIST/MITRE-aligned incident response playbook** — all wrapped in a premium **Streamlit SOC dashboard** with a military-grade dark theme.
