# CYBERSICKER - Autonomous Blue-Team SOC Workbench

> Autonomous LLM-Powered Security Operations Center for Real-Time Threat Triage, Deep Flow Anomaly Detection, and Active Defense Containment.  
> Author: Vrishin Ram.K

---

## Live Deployments & Repository Links

- **Production Console (Vercel):** [https://cybersicker-soc.vercel.app](https://cybersicker-soc.vercel.app)
- **Source Code Repository (GitHub):** [https://github.com/Vrishinram/Cybersicker](https://github.com/Vrishinram/Cybersicker)
- **Primary Feature Branch:** `feat/unified-pipeline-and-cloud-deploy`

---

## System Overview

CYBERSICKER is an enterprise-grade autonomous Blue-Team Security Operations Center (SOC) workbench. It unifies a deep neural autoencoder for real-time network flow anomaly scoring with an autonomous LLM agent (Google Gemini 2.5 Flash) orchestrating multi-vector threat enrichment and active defense containment.

### Dual-Core Architecture

1. **Agentic Reasoning & Triage Core:**
   - **Orchestration LLM:** Google Gemini 2.5 Flash via LangChain and custom multi-intent dispatch pipelines.
   - **Strict Entity Validation:** Zero-fallback RFC 791 IPv4 boundary parsing, case-insensitive CVE extraction, and IEEE MAC OUI prefix resolution.
   - **Live External Threat Intelligence:** Async HTTP clients querying VirusTotal v3, NIST NVD REST API 2.0, and IEEE OUI databases without simulated fallbacks.
   - **Autonomous Playbook RAG:** Persistent ChromaDB vector database housing MITRE ATT&CK v18-aligned Standard Operating Procedures (`SOP-001` through `SOP-007`).

2. **Deep Anomaly Detection & Traffic Ingestion Core:**
   - **Raw Packet Ingestion:** Live parsing of `.pcap`, `.pcapng`, and `.csv` captures via Scapy, reconstructing bidirectional TCP/UDP flows.
   - **Feature Extraction:** Computes 41 statistical NSL-KDD traffic features (`duration`, `protocol_type`, `service`, `flag`, `src_bytes`, `dst_bytes`, `serror_rate`, `same_srv_rate`, etc.).
   - **In-Memory Neural Inference:** Normalization via `StandardScaler` pipeline followed by inference through a pre-trained Keras Autoencoder (`16 -> 8 -> 16`).
   - **Dynamic Thresholding:** Computes reconstruction Mean Squared Error (MSE); flows where `MSE > 0.042` are flagged as anomalies.

3. **Active Defense & Incident Containment:**
   - **Perimeter Firewall Blackholing:** `POST /api/v1/containment/block-ip` emits immediate `iptables` drop rules.
   - **Endpoint Network Isolation:** `POST /api/v1/containment/isolate-host` severs active unauthorized sockets.
   - **OASIS STIX 2.1 Threat Intelligence Bundles:** Generates valid STIX 2.1 JSON packages (`bundle`, `identity`, `incident`, `indicator`, `observed-data`, `relationship`) for SIEM export.

4. **Real-Time Telemetry Streaming:**
   - Full duplex WebSocket stream at `/ws/telemetry`.
   - Server-Sent Events (SSE) stream at `/api/v1/telemetry/stream`.
   - Terminal dock with live JSON syntax highlighting and instantaneous level filtering (`ALL`, `INF`, `WRN`, `ERR`).

---

## Technical Architecture

```
                       +---------------------------------------+
                       |   Operator Browser Interface          |
                       |   Next.js 16 + React 19 + Tailwind    |
                       |   (https://cybersicker-soc.vercel.app)|
                       +-------------------+-------------------+
                                           |
                                           | HTTPS / WSS / SSE
                                           v
                       +---------------------------------------+
                       |   FastAPI High-Performance Backend    |
                       |   (Port 8000 Daemon / Uvicorn)        |
                       +-------------------+-------------------+
                                           |
         +-----------------+---------------+-----------------+-----------------+
         |                 |                                 |                 |
         v                 v                                 v                 v
+-----------------+ +-------------------+             +---------------+ +------------------+
| Gemini 2.5 LLM  | | Live Threat Intel |             | Autoencoder   | | ChromaDB RAG     |
| Multi-Intent    | | - VirusTotal v3   |             | - Keras Model | | - MITRE ATT&CK   |
| Tool Dispatcher | | - NIST NVD 2.0    |             | - Scapy PCAP  | | - SOP Playbooks  |
|                 | | - IEEE OUI Lookup |             | - MSE > 0.042 | |   (001 - 007)    |
+-----------------+ +-------------------+             +---------------+ +------------------+
         |                 |                                 |                 |
         +-----------------+---------------+-----------------+-----------------+
                                           |
                                           v
                       +---------------------------------------+
                       |   Active Defense & Containment Engine |
                       |   - Host Isolation (/isolate-host)    |
                       |   - Ingress Firewall (/block-ip)      |
                       |   - OASIS STIX 2.1 JSON Bundler       |
                       +---------------------------------------+
```

---

## Directory Structure

```
Cybersicker/
├── api.py                           # Primary FastAPI application entrypoint
├── app.py                           # Legacy Streamlit interactive interface
├── agent.py                         # CLI agent dispatch runner
├── autoencoder.py                   # Keras Autoencoder model definitions
├── autoencoder_kdd.keras            # Pre-trained Autoencoder weights (MSE threshold 0.042)
├── scaler.joblib                    # Serialized StandardScaler pipeline
├── KDDTrain+.txt                    # NSL-KDD baseline reference dataset (125,973 records)
├── requirements.txt                 # Python runtime dependencies
│
├── app/
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── ingest.py                # POST /api/v1/scan/traffic (.pcap, .pcapng, .csv)
│   │   ├── containment.py           # Host isolation, IP firewall block, STIX 2.1 exporter
│   │   └── telemetry.py             # WebSocket /ws/telemetry and SSE /api/v1/telemetry/stream
│   ├── services/
│   │   ├── virustotal.py            # Async VirusTotal v3 client
│   │   ├── nvd.py                   # Async NIST NVD 2.0 REST client
│   │   ├── oui.py                   # IEEE MAC OUI resolution database
│   │   ├── playbook_rag.py          # Persistent ChromaDB vector store for SOP playbooks
│   │   ├── pcap_extractor.py        # Scapy flow reconstruction & 41-feature extraction
│   │   ├── traffic_scanner.py       # Autoencoder batch and streaming inference engine
│   │   └── telemetry.py             # Event bus and async queue broadcaster
│   └── utils/
│       ├── entity_parser.py         # RFC 791 IPv4, CVE, and MAC regex validator
│       └── stix_exporter.js         # OASIS STIX 2.1 JSON generator and downloader
│
└── frontend/
    ├── app/
    │   ├── page.tsx                 # Core SOC Workbench interface
    │   ├── layout.tsx               # Root layout and theme injection
    │   ├── globals.css              # Cyberpunk dark theme and terminal CSS
    │   ├── utils/
    │   │   └── stix_exporter.ts     # TypeScript STIX 2.1 export utilities
    │   └── api/v1/                  # Next.js serverless proxy and fallback routes
    ├── components/
    │   ├── Header.tsx               # Top status bar with [RESET SESSION] action control
    │   ├── Sidebar.tsx              # Triage tool arsenal and .pcap/.csv dropzone
    │   ├── ChatFeed.tsx             # Incident feed with conditional defense controls
    │   ├── TelemetryDock.tsx        # Syntax-highlighted streaming log terminal
    │   └── SidebarDropzone.tsx      # Drag-and-drop packet capture ingestion
    └── package.json                 # Next.js 16, React 19, Lucide, Tailwind CSS
```

---

## Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Node.js 20 or higher
- Git

### 1. Backend Environment Setup

```bash
# Clone the repository
git clone https://github.com/Vrishinram/Cybersicker.git
cd Cybersicker

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux / macOS

# Install dependencies
pip install -r requirements.txt

# Configure environment variables (.env)
GOOGLE_API_KEY=your_gemini_api_key_here
VT_API_KEY=your_virustotal_api_key_here        # Optional
NVD_API_KEY=your_nvd_api_key_here              # Optional
```

### 2. Launching the Backend Services

```bash
# Start FastAPI SOC backend daemon on port 8000
python -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload
```

Backend endpoints will be available at:
- REST API Documentation: `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/health`
- SSE Telemetry Stream: `http://127.0.0.1:8000/api/v1/telemetry/stream`
- WebSocket Telemetry: `ws://127.0.0.1:8000/ws/telemetry`

### 3. Frontend Setup (Next.js 16)

```bash
cd frontend

# Install Node modules
npm install

# Run local development server on port 3000
npm run dev

# Or build for production deployment
npm run build
npm run start
```

---

## API Reference

### 1. Network Traffic Analysis & Ingestion

#### `POST /api/v1/scan/traffic`
Accepts multipart file upload (`.pcap`, `.pcapng`, `.csv`) or JSON payload. Reconstructs network flows, extracts NSL-KDD features, and performs Autoencoder MSE scoring.

**Response:**
```json
{
  "success": true,
  "data": {
    "source": "capture.pcap",
    "total_flows": 1248,
    "anomalies_detected": 23,
    "anomaly_percentage": 1.84,
    "mean_mse": 0.0512,
    "max_mse": 0.089,
    "threshold": 0.042,
    "verdict": "HIGH RISK - Active Attack Vector Detected",
    "top_anomalous_endpoints": [
      {
        "flow_id": "185.220.101.43:24102->192.168.1.1:80/tcp",
        "src_ip": "185.220.101.43",
        "dst_ip": "192.168.1.1",
        "src_port": 24102,
        "dst_port": 80,
        "protocol": "tcp",
        "service": "http",
        "mse": 0.089,
        "anomaly_flag": true
      }
    ]
  }
}
```

### 2. Autonomous Incident Triage

#### `POST /api/chat`
Dispatches operator natural language prompts to Google Gemini 2.5 Flash, dynamically invoking tools based on detected entities.

**Example Request:**
```json
{
  "message": "Analyze IP 185.220.101.43 and query CVE-2024-3094"
}
```

#### `POST /api/tools/all`
Runs the complete 5-stage triage pipeline sequentially (Scanner + VirusTotal + NIST NVD + MAC OUI + Playbook RAG).

### 3. Active Defense & Containment

#### `POST /api/v1/containment/block-ip`
```json
{
  "ip_address": "185.220.101.43",
  "firewall_type": "iptables"
}
```
**Response:**
```json
{
  "status": "BLOCKED",
  "command": "iptables -A INPUT -s 185.220.101.43 -j DROP",
  "timestamp": "2026-10-31T15:30:00Z"
}
```

#### `POST /api/v1/containment/isolate-host`
```json
{
  "host_ip": "192.168.1.105",
  "reason": "Compromised by Mirai Botnet"
}
```

#### `POST /api/v1/containment/export-stix`
Generates an OASIS STIX 2.1 incident response bundle containing identity, incident, indicator, observed-data, and relationship objects.

---

## Standard Operating Procedures (ChromaDB Playbooks)

CYBERSICKER integrates authoritative incident response playbooks aligned with NIST CSF 2.0 and MITRE ATT&CK v18:

| ID | Title | Threat Category | Primary Actions |
|---|---|---|---|
| **SOP-001** | IoT Botnet Infection Response | Mirai, Mozi, Gafgyt | Edge quarantine, CNC socket termination, credential rotation |
| **SOP-002** | Volumetric SYN/ICMP Flood Mitigation | Denial of Service (DDoS) | Boundary rate-limiting, SYN cookie activation, upstream scrubbing |
| **SOP-003** | IoT Ransomware & Firmware Extortion | Ransomware / Data Destruction | Out-of-band management isolation, snapshot restoration, forensic dump |
| **SOP-004** | Unauthorized Lateral Movement | Pass-the-Hash / SSH Hijack | Host isolation, Kerberos ticket purge, segmented VLAN separation |
| **SOP-005** | Remote Code Execution & Supply Chain | XZ Utils (CVE-2024-3094), Log4j | Package rollback, vulnerability patching, egress boundary filter |
| **SOP-006** | Rogue Hardware & ARP Spoofing | Hardware Implant / MitM | MAC ACL enforcement, port security shutdown, switch audit |
| **SOP-007** | Automated Perimeter Boundary Firewall Block | Perimeter Containment | Border firewall drop injection, STIX 2.1 distribution |

---

## Machine Learning Model Specifications

- **Architecture:** Deep Autoencoder (`Input -> Dense(16, ReLU) -> Dense(8, ReLU) -> Dense(16, ReLU) -> Output(Linear)`)
- **Loss Function:** Mean Squared Error (MSE)
- **Baseline Training Data:** NSL-KDD (`KDDTrain+.txt`, 125,973 nominal and anomalous flows)
- **Dimensionality Reduction:** 95% variance PCA projection
- **Decision Threshold:** `MSE > 0.042` flags anomalous flow distributions with zero manual threshold tuning required.

---

## Production Security & Governance

- Strict RFC 791 validation prevents malformed address injection.
- Zero mock fallbacks for live threat intelligence lookups when API keys are configured.
- Automated client-side STIX 2.1 bundle export complies with US-CERT and OASIS Open standards.
- Session reset flushes chat states and telemetry logs cleanly back to ready state.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
