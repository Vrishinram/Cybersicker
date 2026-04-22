# CYBERSICKER — Agentic AI Cyberattack Detection for IoT Environments

> **Autonomous LLM-Powered Security Operations Center for IoT Threat Detection & Response**  
> Built by **Vrishin Ram.K** | Dhanalakshmi Srinivasan University, Dept. of Cybersecurity

***REMOVED***!***REMOVED***Agentic AI***REMOVED***(https://img.shields.io/badge/Type-Agentic%20AI-purple)***REMOVED***(https://python.langchain.com/docs/concepts/agents)
***REMOVED***!***REMOVED***Python***REMOVED***(https://img.shields.io/badge/Python-3.9+-blue)***REMOVED***(https://www.python.org/)
***REMOVED***!***REMOVED***License***REMOVED***(https://img.shields.io/badge/License-MIT-green)***REMOVED***(#license)
***REMOVED***!***REMOVED***LLM***REMOVED***(https://img.shields.io/badge/LLM-Google%20Gemini%202.5%20Flash-red)***REMOVED***(https://ai.google.dev/)

---

## 🎯 Project Overview

**CYBERSICKER** is a **dual-core intelligent system** that fuses **agentic AI** with **IoT cyberattack detection**:

🤖 **Agentic AI Core:** Autonomous LLM agent (Google Gemini 2.5 Flash) that orchestrates 5+ security tools to investigate threats, query threat intelligence APIs, and consult incident response playbooks.  
🔍 **Detection Core:** Deep learning autoencoder + ML anomaly detection on network traffic to identify botnet infections, DDoS attacks, ransomware, and lateral movement in IoT environments.

It simulates an **autonomous blue-team SOC analyst** that can independently reason, make decisions, and respond to security incidents in real-time.

### The Dual-Core System

#### 🤖 **Agentic AI Engine**
- **Brain:** Google Gemini 2.5 Flash LLM
- **Framework:** LangChain agent orchestrator
- **Tools:** 5 autonomous security investigation tools
  - Network anomaly scanner (autoencoder)
  - VirusTotal IP reputation checker
  - MAC address device lookup
  - NIST CVE database queries
  - Incident response playbook consultant (RAG)
- **Capability:** Autonomous reasoning, tool selection, threat analysis

#### 🔍 **IoT Threat Detection**
- **Algorithm:** Deep neural network autoencoder + PCA
- **Dataset:** NSL-KDD (19 MB labeled network traffic)
- **Detects:** Botnet infections, DDoS floods, ransomware, lateral movement
- **Accuracy:** Real-time anomaly scoring (MSE threshold-based)
- **Output:** Flagged records with anomaly count & percentage

---

## 🏗️ Technology Stack

| Layer | Technology |
|---|---|
| **Frontend / Dashboard** | Streamlit (Python) with custom military-grade dark CSS |
| **LLM Brain** | Google Gemini 2.5 Flash via `langchain_google_genai` |
| **Agent Framework** | LangChain (`create_agent`, `@tool` decorators) |
| **Anomaly Detection ML** | TensorFlow/Keras Autoencoder + Scikit-Learn (PCA, StandardScaler) |
| **Playbook RAG** | LangChain `TextLoader` → `CharacterTextSplitter` → `HuggingFaceEmbeddings` → `ChromaDB` |
| **Threat Intelligence** | VirusTotal API, NIST NVD API, macvendors.com API |
| **Dataset** | KDD Cup 1999 (NSL-KDD) — 19 MB network traffic dataset |

---

## 🔄 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      👤 User Input                          │
│              (Chat Dashboard or CLI Terminal)               │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │  🤖 Gemini 2.5 Flash Agent     │
        │      (LangChain Orchestrator)  │
        └────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   Network Scanner  VirusTotal API   NIST CVE DB
   (Autoencoder)    IP Reputation    CVE Lookup
        │                │                │
        └────────────────┼────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   MAC Vendor      Playbook RAG    Incident Response
   Lookup          (ChromaDB)       Strategy
        │                │                │
        └────────────────┼────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │   📊 Formatted SOC Report      │
        │   (Dashboard or Terminal)      │
        └────────────────────────────────┘
```

---

## 📁 File Structure

### Core Components

| File | Lines | Description |
|---|---|---|
| **app.py** | 542 | Streamlit SOC dashboard with cyberpunk UI, agent integration |
| **agent.py** | 121 | CLI terminal agent for direct command-line interaction |
| **autoencoder.py** | 49 | Deep neural network for anomaly detection in network traffic |
| **api.py** | — | Shared API client utilities |
| **cyber_test.py** | 14 | Test script for Gemini API connectivity |

### Configuration & Data

| File | Description |
|---|---|
| **playbook.env.txt** | 380-line incident response playbook (NIST CSF 2.0 + MITRE ATT&CK aligned) |
| **KDDTrain+.txt** | ~19 MB NSL-KDD network traffic dataset (labeled for supervised learning) |
| **scitely_models.json** | Threat model configurations |
| **playbook.env.txt** | IR playbook v2.0 |
| **requirements.txt** | Python package dependencies |

### Frontend (Next.js Optional)

| Path | Purpose |
|---|---|
| **frontend/** | Optional Next.js TypeScript dashboard (alternative to Streamlit) |

---

## 🛠️ Installation

### Prerequisites
- **Python 3.9+**
- **pip** package manager
- **Google API Key** (for Gemini LLM)
- **VirusTotal API Key** (optional, for IP reputation checks)

### Setup

```bash
# Clone the repository
git clone https://github.com/Vrishinram/Cybersicker.git
cd Cybersicker

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate  # On Windows
source venv/bin/activate  # On macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Configure API keys
# Option 1: Create .env file
echo GOOGLE_API_KEY=your_api_key_here > .env
echo VT_API_KEY=your_virustotal_key_here >> .env

# Option 2: Export as environment variables
set GOOGLE_API_KEY=your_api_key_here      # Windows
set VT_API_KEY=your_virustotal_key_here   # Windows

export GOOGLE_API_KEY=your_api_key_here   # macOS/Linux
export VT_API_KEY=your_virustotal_key_here  # macOS/Linux
```

---

## 🚀 Usage

### 1. Streamlit Dashboard (Recommended)

```bash
streamlit run app.py
```

Then open `http://localhost:8501` in your browser.

**Features:**
- 🎨 Cyberpunk military SOC aesthetic
- 💬 Chat-based threat investigation
- 📊 Real-time metric cards
- 🔄 Autonomous tool orchestration

### 2. CLI Terminal Agent

```bash
python agent.py
```

**Example commands:**
```
> scan d:\CYBERSICKER\KDDTrain+.txt
> check ip 8.8.8.8
> lookup mac 00:1A:2B:3C:4D:5E
> cve sudo
> playbook botnet response
```

---

## 🔧 Core Tools (Agent Capabilities)

### 1. Network Scanner
```python
network_scanner(file_path: str) -> str
```
- Scans CSV/TXT network traffic logs
- Uses autoencoder to detect anomalies
- Returns count and percentage of anomalies

### 2. IP Reputation Check
```python
check_ip_virustotal(ip_address: str) -> str
```
- Queries VirusTotal API
- Returns vendor detections and confidence scores
- Identifies malicious IPs

### 3. MAC Address Lookup
```python
lookup_mac_address(mac: str) -> str
```
- Identifies device manufacturer from OUI
- Uses macvendors.com API
- Useful for IoT device inventory

### 4. CVE Database Query
```python
query_cve_database(product: str) -> str
```
- Retrieves vulnerabilities from NIST NVD API
- Returns CVSS scores and severity
- Links to official CVE records

### 5. Incident Response Playbook
```python
consult_playbook(query: str) -> str
```
- Semantic search over playbook using RAG
- Uses ChromaDB + HuggingFace embeddings
- Returns relevant incident response procedures

---

## 📊 Machine Learning Details

### Autoencoder Architecture

A deep neural network trained on normal network traffic:

```
Input Layer (n features via PCA)
    ↓
Dense(16, ReLU)  ***REMOVED***Encoder 1***REMOVED***
    ↓
Dense(8, ReLU)   ***REMOVED***Bottleneck***REMOVED***
    ↓
Dense(16, ReLU)  ***REMOVED***Decoder 1***REMOVED***
    ↓
Dense(n, Linear) ***REMOVED***Output***REMOVED***
```

**Training Pipeline:**
1. Extract numeric columns from CSV
2. Apply StandardScaler normalization
3. Apply PCA (95% variance retention) for dimensionality reduction
4. Train autoencoder on normal traffic (5 epochs, batch size 256)
5. Calculate Mean Squared Error (MSE) for each record
6. Flag records with MSE > 0.5 as anomalies

**Dataset:** NSL-KDD (19 MB)
- 125,973 training records
- Protocol types: TCP, UDP, ICMP
- Attack labels: DoS, Probe, R2L, U2R, Normal

---

## 📋 Incident Response Playbook

The **playbook.env.txt** includes:

### Standard Operating Procedures (SOPs)
- **SOP-001:** IoT Botnet Infection Response (Mirai, Mozi, etc.)
- **SOP-002:** ICMP Flood / DDoS Mitigation
- **SOP-003:** IoT Ransomware Containment

### Frameworks
- **NIST CSF 2.0** compliance mapping
- **MITRE ATT&CK for ICS/IoT** tactic coverage
- **Escalation Matrix** (SEV-1 to SEV-4)

### Network Architecture
- 5-VLAN isolation strategy
- Inter-VLAN ACL rules for zero-trust
- Evidence preservation & chain of custody

---

## 🔐 Configuration

### Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `GOOGLE_API_KEY` | ✅ Yes | Google Gemini API access |
| `VT_API_KEY` | ❌ No | VirusTotal threat intelligence |

### API Updates

Update `.env` file or run:
```bash
# Windows
set GOOGLE_API_KEY=new_key

# macOS/Linux
export GOOGLE_API_KEY=new_key
```

---

## 📦 Dependencies

See `requirements.txt`:

```
streamlit>=1.28.0
langchain>=0.1.0
langchain-google-genai>=0.0.0
google-generativeai>=0.3.0
tensorflow>=2.13.0
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
chromadb>=0.4.0
sentence-transformers>=2.2.0
requests>=2.31.0
python-dotenv>=1.0.0
```

Install all at once:
```bash
pip install -r requirements.txt
```

---

## 🧪 Testing

### Test Gemini API Connection

```bash
python cyber_test.py
```

### Test Individual Tools

```python
# Test autoencoder
from autoencoder import analyze_network_data
df = pd.read_csv("KDDTrain+.txt")
anomalies = analyze_network_data(df)

# Test VirusTotal
from agent import check_ip_virustotal
result = check_ip_virustotal("1.1.1.1")
```

---

## 📈 Performance Metrics

- **Autoencoder Training:** ~30 seconds on modern CPU
- **Anomaly Detection:** ~2-5 seconds per scan (19 MB dataset)
- **API Response:** ~1-3 seconds (VirusTotal, CVE DB)
- **LLM Reasoning:** ~2-5 seconds (Gemini)

---

## 🏆 Use Cases

1. **IoT Botnet Detection** - Identify Mirai/Mozi command & control traffic
2. **DDoS Mitigation** - Detect volumetric attacks via ICMP/SYN anomalies
3. **Threat Intelligence Integration** - Correlate internal logs with external feeds
4. **Incident Response Automation** - Autonomous investigation & playbook consultation
5. **Security Awareness Training** - Blue-team SOC analyst simulation

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see ***REMOVED***LICENSE***REMOVED***(LICENSE) file for details.

---

## 👤 Author

**Vrishin Ram.K**  
🏫 Dhanalakshmi Srinivasan University, Department of Cybersecurity  
📧 ***REMOVED***Contact***REMOVED***(mailto:vrishinram.k@dsu.edu.in)

---

## 🔗 Resources

- **Google Gemini API:** https://ai.google.dev/
- **LangChain:** https://python.langchain.com/
- **VirusTotal API:** https://www.virustotal.com/api/
- **NIST NVD:** https://nvd.nist.gov/
- **NSL-KDD Dataset:** https://www.unb.ca/cic/datasets/nsl-kdd.html
- **MITRE ATT&CK:** https://attack.mitre.org/

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing and research only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.

---

<p align="center">
  <strong>Made with 🛡️ for cybersecurity</strong>
</p>
