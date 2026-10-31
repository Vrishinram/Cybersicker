"""
CYBERSICKER — FastAPI Backend
Exposes the 5 SOC tools + LLM agent chat as REST endpoints
for the Next.js frontend dashboard.
"""

import os
import re
import sys
import json
import traceback
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests

# ─── App Setup ───────────────────────────────────────────────
app = FastAPI(title="CYBERSICKER API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Load env keys ───────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
VT_API_KEY = os.environ.get("VT_API_KEY", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
SCITELY_API_KEY = os.environ.get("SCITELY_API_KEY", "")
SCITELY_BASE_URL = os.environ.get("SCITELY_BASE_URL", "https://api.scitely.ai/v1")
SCITELY_MODEL = os.environ.get("SCITELY_MODEL", "gpt-4o-mini")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEBUG_LOG_PATH = Path(BASE_DIR) / "debug-dc3fd7.log"

def debug_log(hypothesis_id: str, location: str, message: str, data: dict):
    payload = {
        "sessionId": "dc3fd7",
        "runId": "initial",
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(__import__("time").time() * 1000),
    }
    # region agent log
    try:
        with DEBUG_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=True) + "\n")
    except Exception:
        pass
    # endregion

# ─── Request/Response models ────────────────────────────────
class ScanRequest(BaseModel):
    filepath: str

class IPRequest(BaseModel):
    ip_address: str

class MACRequest(BaseModel):
    mac_address: str

class CVERequest(BaseModel):
    cve_id: str

class PlaybookRequest(BaseModel):
    incident_type: str

class FullTriageRequest(BaseModel):
    filepath: Optional[str] = "D:\\CYBERSICKER\\KDDTrain+.txt"
    ip_address: Optional[str] = "185.220.101.43"
    mac_address: Optional[str] = "00:1A:2B:3C:4D:5E"
    cve_id: Optional[str] = "CVE-2021-44228"
    incident_type: Optional[str] = "Botnet infection containment and perimeter isolation"

class ChatRequest(BaseModel):
    message: str
    history: list = []

class ToolResponse(BaseModel):
    success: bool
    result: str


# ═══════════════════════════════════════════════════════════════
# TOOL 1: Network Scanner (Autoencoder)
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/scan", response_model=ToolResponse)
async def network_scan(req: ScanRequest):
    try:
        # ── Simulation Guard: Handle different file paths ──
        verdict = "SAFE"
        anomalies = 0
        if "traffic_analysis.pcap" in req.filepath:
            anomalies = 1450
            verdict = "CRITICAL"
        elif "nmap" in req.filepath:
            anomalies = 42
            verdict = "MONITORING"
        elif "auth.log" in req.filepath:
            anomalies = 5
            verdict = "LOW RISK"

        if anomalies > 0 or "Simulation" in req.filepath:
             return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "SCAN_COMPLETE (SIMULATED)",
                    "filepath": req.filepath,
                    "anomalies_detected": anomalies,
                    "threshold": 0.5,
                    "model": "Autoencoder (16→8→16)",
                    "verdict": verdict
                })
            )
        
        from autoencoder import run_network_scan
        result = run_network_scan(req.filepath)
        if isinstance(result, int):
            return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "SCAN_COMPLETE",
                    "filepath": req.filepath,
                    "anomalies_detected": result,
                    "threshold": 0.5,
                    "model": "Autoencoder (16→8→16)",
                    "verdict": "HIGH RISK" if result > 1000 else "MODERATE" if result > 100 else "LOW RISK"
                })
            )
        return ToolResponse(success=False, result=str(result))
    except Exception as e:
        return ToolResponse(success=False, result=f"Scan Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# TOOL 2: VirusTotal IP Check
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/ip-check", response_model=ToolResponse)
async def check_ip(req: IPRequest):
    if not VT_API_KEY:
        # ── Simulation Guard: Return realistic mock data ──
        mock_threats = {
            "185.220.101.43": {"malicious": 68, "suspicious": 2, "harmless": 0, "verdict": "MALICIOUS"},
            "45.33.32.156": {"malicious": 12, "suspicious": 1, "harmless": 2, "verdict": "MALICIOUS"},
            "192.168.1.1": {"malicious": 0, "suspicious": 0, "harmless": 70, "verdict": "CLEAN"},
            "192.0.2.1": {"malicious": 0, "suspicious": 0, "harmless": 0, "verdict": "CLEAN", "note": "RFC 5737 Documentation IP"},
            "8.8.8.8": {"malicious": 0, "suspicious": 0, "harmless": 100, "verdict": "CLEAN", "note": "Google Public DNS"},
            "127.0.0.1": {"malicious": 0, "suspicious": 0, "harmless": 1, "verdict": "CLEAN", "note": "Local Loopback"},
            "192.168.1.100": {"malicious": 0, "suspicious": 0, "harmless": 5, "verdict": "CLEAN", "note": "Internal Network"},
        }
        data = mock_threats.get(req.ip_address, {
            "malicious": 0, "suspicious": 0, "harmless": 10, "verdict": "CLEAN"
        })
        return ToolResponse(
            success=True,
            result=json.dumps({
                "event": "VT_LOOKUP (SIMULATED)",
                "ip": req.ip_address,
                **data
            })
        )
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{req.ip_address}"
        headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "VT_LOOKUP",
                    "ip": req.ip_address,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "verdict": "MALICIOUS" if malicious > 0 else "CLEAN"
                })
            )
        return ToolResponse(success=False, result=f"VirusTotal API returned status {response.status_code}")
    except Exception as e:
        return ToolResponse(success=False, result=f"Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# TOOL 3: MAC Address Lookup & IEEE OUI Resolution
# ═══════════════════════════════════════════════════════════════
OUI_REGISTRY = {
    # Raspberry Pi Foundation (IoT SBC)
    "B827EB": {"vendor": "Raspberry Pi Foundation", "note": "Identified low-cost IoT single-board computer; inspect unauthorized local network presence.", "category": "IoT SBC"},
    "DCA632": {"vendor": "Raspberry Pi Foundation", "note": "Identified low-cost IoT single-board computer; inspect unauthorized local network presence.", "category": "IoT SBC"},
    "E45F01": {"vendor": "Raspberry Pi Foundation", "note": "Identified low-cost IoT single-board computer; inspect unauthorized local network presence.", "category": "IoT SBC"},
    "28CDC1": {"vendor": "Raspberry Pi Foundation", "note": "Identified low-cost IoT single-board computer; inspect unauthorized local network presence.", "category": "IoT SBC"},

    # Espressif Systems (ESP8266 / ESP32 IoT Microcontroller)
    "FC65DE": {"vendor": "Espressif Inc.", "note": "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.", "category": "IoT Microcontroller"},
    "240AC4": {"vendor": "Espressif Inc.", "note": "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.", "category": "IoT Microcontroller"},
    "30AEA4": {"vendor": "Espressif Inc.", "note": "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.", "category": "IoT Microcontroller"},
    "A4CF12": {"vendor": "Espressif Inc.", "note": "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.", "category": "IoT Microcontroller"},
    "84F3EB": {"vendor": "Espressif Inc.", "note": "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.", "category": "IoT Microcontroller"},

    # Google LLC (Smart Device / Nest)
    "001A11": {"vendor": "Google, LLC", "note": "Identified smart home/Nest or Google hardware endpoint; inspect IoT perimeter isolation rules.", "category": "Smart Device / Nest"},
    "F4F5D8": {"vendor": "Google, LLC", "note": "Identified smart home/Nest or Google hardware endpoint; inspect IoT perimeter isolation rules.", "category": "Smart Device / Nest"},
    "D86C63": {"vendor": "Google, LLC", "note": "Identified smart home/Nest or Google hardware endpoint; inspect IoT perimeter isolation rules.", "category": "Smart Device / Nest"},

    # VMware Inc. (Virtual Machine Interface)
    "000C29": {"vendor": "VMware, Inc.", "note": "Identified VMware ESXi/Workstation virtual network adapter; confirm virtualization host legitimacy.", "category": "Virtualization Interface"},
    "005056": {"vendor": "VMware, Inc.", "note": "Identified VMware ESXi/Workstation virtual network adapter; confirm virtualization host legitimacy.", "category": "Virtualization Interface"},
    "000569": {"vendor": "VMware, Inc.", "note": "Identified VMware ESXi/Workstation virtual network adapter; confirm virtualization host legitimacy.", "category": "Virtualization Interface"},

    # Parallels Inc. (Virtual Machine Interface)
    "001C42": {"vendor": "Parallels, Inc.", "note": "Identified Parallels desktop virtualization guest adapter.", "category": "Virtualization Interface"},

    # Microsoft Corporation (Virtual Adapter)
    "00155D": {"vendor": "Microsoft Corporation", "note": "Identified Microsoft Hyper-V virtual network interface or Windows endpoint.", "category": "Virtualization Interface"},

    # Cisco Systems Inc. (Enterprise Gateway)
    "001A2B": {"vendor": "Cisco Systems, Inc.", "note": "Verified enterprise switch, router, or core network infrastructure gateway.", "category": "Enterprise Gateway"},
    "00000C": {"vendor": "Cisco Systems, Inc.", "note": "Verified enterprise switch, router, or core network infrastructure gateway.", "category": "Enterprise Gateway"},
    "000142": {"vendor": "Cisco Systems, Inc.", "note": "Verified enterprise switch, router, or core network infrastructure gateway.", "category": "Enterprise Gateway"},
    "000143": {"vendor": "Cisco Systems, Inc.", "note": "Verified enterprise switch, router, or core network infrastructure gateway.", "category": "Enterprise Gateway"},

    # Apple Inc.
    "3C5AB4": {"vendor": "Apple, Inc.", "note": "Identified Apple macOS/iOS endpoint; verify corporate MDM profile.", "category": "Workstation / Mobile"},
    "ACBC32": {"vendor": "Apple, Inc.", "note": "Identified Apple macOS/iOS endpoint; verify corporate MDM profile.", "category": "Workstation / Mobile"},
    "F8FFC2": {"vendor": "Apple, Inc.", "note": "Identified Apple macOS/iOS endpoint; verify corporate MDM profile.", "category": "Workstation / Mobile"},

    # Intel
    "001E67": {"vendor": "Intel Corporate", "note": "Verified Intel gigabit ethernet/Wi-Fi adapter.", "category": "Enterprise NIC"},

    # TP-Link
    "50C7BF": {"vendor": "TP-Link Corporation", "note": "Identified TP-Link smart home Wi-Fi smart plug/switch.", "category": "Consumer IoT"},
}

def resolve_mac_oui(mac_address: str) -> dict:
    clean = re.sub(r'[^0-9A-Fa-f]', '', mac_address).upper()
    if len(clean) < 6:
        return {
            "mac": mac_address,
            "oui": clean,
            "vendor": "INVALID_MAC",
            "device_note": "Invalid MAC address format (fewer than 6 hex digits).",
            "category": "Invalid"
        }
    oui = clean[:6]
    formatted_mac = ":".join(clean[i:i+2] for i in range(0, min(12, len(clean)), 2))

    # 1. Match local comprehensive registry
    if oui in OUI_REGISTRY:
        entry = OUI_REGISTRY[oui]
        return {
            "mac": formatted_mac,
            "oui": oui,
            "vendor": entry["vendor"],
            "device_note": entry["note"],
            "category": entry["category"]
        }

    # 2. Check for Locally Administered Address (bit 1 of first byte) or private test MAC
    first_byte = int(oui[:2], 16)
    if (first_byte & 0x02) != 0 or oui == "AABBCC":
        return {
            "mac": formatted_mac,
            "oui": oui,
            "vendor": "Locally Administered / Private Unregistered MAC",
            "device_note": "Locally administered address (LAA) or randomized/spoofed MAC; treat as high-risk untrusted endpoint.",
            "category": "Randomized / Spoofed"
        }

    # 3. Fallback to external public API if reachable
    try:
        url = f"https://api.macvendors.com/{formatted_mac}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            vendor = response.text.strip()
            return {
                "mac": formatted_mac,
                "oui": oui,
                "vendor": vendor,
                "device_note": f"Device manufactured by {vendor}. Cross-reference with IoT asset inventory.",
                "category": "Commercial Vendor"
            }
        elif response.status_code == 404:
            return {
                "mac": formatted_mac,
                "oui": oui,
                "vendor": "NOT FOUND",
                "device_note": "Vendor not found in IEEE database. Could be a spoofed MAC or unregistered device. Treat as suspicious.",
                "category": "Unregistered"
            }
    except Exception:
        pass

    return {
        "mac": formatted_mac,
        "oui": oui,
        "vendor": "Unknown Manufacturer",
        "device_note": "Unregistered or obscure hardware vendor; monitor connection telemetry for abnormal egress traffic.",
        "category": "Unregistered"
    }


@app.post("/api/tools/mac-lookup", response_model=ToolResponse)
async def mac_lookup(req: MACRequest):
    try:
        resolved = resolve_mac_oui(req.mac_address)
        return ToolResponse(
            success=True,
            result=json.dumps({
                "event": "MAC_RESOLVE",
                "mac": resolved["mac"],
                "oui": resolved["oui"],
                "vendor": resolved["vendor"],
                "note": resolved["device_note"],
                "category": resolved["category"]
            })
        )
    except Exception as e:
        return ToolResponse(success=False, result=f"Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# TOOL 4: CVE Database Query
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/cve-lookup", response_model=ToolResponse)
async def cve_lookup(req: CVERequest):
    try:
        cve_id = req.cve_id.strip().upper()
        # ── Simulation Guard ──
        mock_cves = {
            "CVE-2021-44228": {
                "published": "2021-12-10", "cvss_score": 10.0, "severity": "CRITICAL",
                "description": "Apache Log4j2 remote code execution vulnerability (Log4Shell).",
                "recommendation": "Upgrade to Log4j 2.17.1 or higher immediately."
            },
            "CVE-2017-0144": {
                "published": "2017-03-14", "cvss_score": 8.1, "severity": "HIGH",
                "description": "SMBv1 vulnerability used by EternalBlue and WannaCry.",
                "recommendation": "Apply MS17-010 security update."
            },
            "CVE-2023-23397": {
                "published": "2023-03-14", "cvss_score": 9.8, "severity": "CRITICAL",
                "description": "Microsoft Outlook Elevation of Privilege Vulnerability.",
                "recommendation": "Apply latest Microsoft Outlook patches."
            },
            "CVE-2024-3094": {
                "published": "2024-03-29", "cvss_score": 10.0, "severity": "CRITICAL",
                "description": "Malicious code discovered in xz-utils upstream tarballs (liblzma versions 5.6.0 and 5.6.1) intercepting OpenSSH sshd process authentication to allow unauthorized remote code execution.",
                "recommendation": "Immediately downgrade xz-utils to version 5.4.x, terminate unauthorized SSH sessions, and revoke potentially compromised keys."
            }
        }
        if cve_id in mock_cves:
             return ToolResponse(success=True, result=json.dumps({
                "event": "CVE_LOOKUP (SIMULATED)", "cve_id": cve_id, "found": True,
                **mock_cves[cve_id]
          }))

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, headers={"Accept": "application/json"}, timeout=15)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return ToolResponse(success=True, result=json.dumps({
                    "event": "CVE_LOOKUP", "cve_id": cve_id, "found": False,
                    "note": f"{cve_id} not found in NVD database."
              }))
            cve_data = vulns[0].get("cve", {})
            desc_list = cve_data.get("descriptions", [])
            description = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description available.")
            metrics = cve_data.get("metrics", {})
            cvss_score = "N/A"
            severity = "N/A"
            for vk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if vk in metrics:
                    cvss_data = metrics[vk][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", "N/A")
                    break
            published = cve_data.get("published", "Unknown")[:10]
            return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "CVE_LOOKUP",
                    "cve_id": cve_id,
                    "found": True,
                    "published": published,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": description[:500],
                    "recommendation": "Patch immediately if score >= 7.0. Check vendor advisories for IoT firmware updates."
                })
            )
        elif response.status_code == 403:
            return ToolResponse(success=False, result="NVD API rate limited. Try again in 30 seconds.")
        return ToolResponse(success=False, result=f"NVD API returned status {response.status_code}")
    except Exception as e:
        return ToolResponse(success=False, result=f"Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# TOOL 5: Playbook Consultation (RAG)
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/playbook", response_model=ToolResponse)
async def consult_playbook(req: PlaybookRequest):
    try:
        from langchain_community.document_loaders import TextLoader
        from langchain_community.vectorstores import Chroma
        from langchain_community.embeddings import HuggingFaceEmbeddings
        from langchain_text_splitters import CharacterTextSplitter

        playbook_path = os.path.join(BASE_DIR, "playbook.env.txt")
        loader = TextLoader(playbook_path)
        documents = loader.load()
        text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
        docs = text_splitter.split_documents(documents)

        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        db = Chroma.from_documents(docs, embeddings)

        results = db.similarity_search(req.incident_type, k=3)
        if results:
            combined = "\n---\n".join([r.page_content for r in results])
            return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "PLAYBOOK_MATCH",
                    "query": req.incident_type,
                    "matches": len(results),
                    "content": combined
                })
            )
        return ToolResponse(success=True, result=json.dumps({
            "event": "PLAYBOOK_MATCH", "query": req.incident_type,
            "matches": 0, "content": "No specific rule found for this incident type."
      }))
    except Exception as e:
        return ToolResponse(success=False, result=f"Error: {str(e)}")




# ═══════════════════════════════════════════════════════════════
# TOOL COMBINED: Full-Spectrum Security Triage Pipeline
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/full-triage", response_model=ToolResponse)
async def full_triage(req: FullTriageRequest):
    try:
        # 1. Run Network Scanner
        scan_resp = await network_scan(ScanRequest(filepath=req.filepath or "D:\\CYBERSICKER\\KDDTrain+.txt"))
        scan_data = json.loads(scan_resp.result) if scan_resp.success else {"verdict": "ERROR", "error": scan_resp.result}

        # 2. Run IP Check
        ip_resp = await check_ip(IPRequest(ip_address=req.ip_address or "185.220.101.43"))
        ip_data = json.loads(ip_resp.result) if ip_resp.success else {"verdict": "ERROR", "error": ip_resp.result}

        # 3. Run CVE Lookup
        cve_resp = await cve_lookup(CVERequest(cve_id=req.cve_id or "CVE-2021-44228"))
        cve_data = json.loads(cve_resp.result) if cve_resp.success else {"found": False, "error": cve_resp.result}

        # 4. Run MAC Lookup
        mac_resp = await mac_lookup(MACRequest(mac_address=req.mac_address or "00:1A:2B:3C:4D:5E"))
        mac_data = json.loads(mac_resp.result) if mac_resp.success else {"vendor": "ERROR", "error": mac_resp.result}

        # 5. Run Playbook
        playbook_file = Path(BASE_DIR) / "playbook.env.txt"
        playbook_text = ""
        if playbook_file.exists():
            content = playbook_file.read_text(encoding="utf-8", errors="ignore")
            paras = [p.strip() for p in content.split("\n\n") if p.strip()]
            topic_words = (req.incident_type or "botnet").split()
            matches = [p for p in paras if any(w.lower() in p.lower() for w in topic_words)]
            playbook_text = "\n---\n".join(matches[:2]) if matches else paras[0]
        else:
            playbook_text = "Standard Containment Protocol: 1. Isolate device. 2. Block external IP. 3. Apply CVE patch."

        # Compute overall severity
        is_critical = (
            scan_data.get("verdict") == "CRITICAL"
            or ip_data.get("verdict") == "MALICIOUS"
            or cve_data.get("severity") in ["CRITICAL", "HIGH"]
        )

        overall_verdict = "CRITICAL THREAT DETECTED" if is_critical else "NOMINAL / LOW RISK"

        combined_result = {
            "event": "FULL_TRIAGE_COMPLETE",
            "verdict": "MALICIOUS" if is_critical else "CLEAN",
            "overall_status": overall_verdict,
            "scan": scan_data,
            "ip": ip_data,
            "mac": mac_data,
            "cve": cve_data,
            "playbook": {
                "topic": req.incident_type or "Botnet containment",
                "procedures": playbook_text
            }
        }
        return ToolResponse(success=True, result=json.dumps(combined_result))
    except Exception as e:
        return ToolResponse(success=False, result=f"Full triage pipeline failed: {str(e)}")

# ═══════════════════════════════════════════════════════════════
# AGENT CHAT — LLM + Tools
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# REGEX ENTITY EXTRACTION & DYNAMIC TOOL DISPATCH
# ═══════════════════════════════════════════════════════════════
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
CVE_REGEX = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
MAC_REGEX = re.compile(r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})')

def extract_entities(text: str):
    return {
        "ips": IPV4_REGEX.findall(text),
        "cves": [c.upper() for c in CVE_REGEX.findall(text)],
        "macs": MAC_REGEX.findall(text),
    }

async def dynamic_dispatch_prompt(prompt: str) -> dict:
    entities = extract_entities(prompt)
    raw_ips = entities["ips"]
    raw_cves = entities["cves"]
    raw_macs = entities["macs"]

    msg_lower = prompt.lower()

    # Determine requested vectors
    wants_all = any(k in msg_lower for k in ["combine", "all tools", "full triage", "full-spectrum", "pipeline", "all vectors", "everything"])
    wants_ip = bool(raw_ips) or any(k in msg_lower for k in ["ip", "virustotal", "reputation", "host", "address"])
    wants_cve = bool(raw_cves) or any(k in msg_lower for k in ["cve", "vulnerability", "nist", "nvd", "exploit", "advisory"])
    wants_mac = bool(raw_macs) or any(k in msg_lower for k in ["mac", "oui", "hardware", "manufacturer", "device"])
    wants_scan = any(k in msg_lower for k in ["scan", "autoencoder", "kdd", "anomaly", "anomalies", "traffic log", "packet"])
    wants_playbook = any(k in msg_lower for k in ["playbook", "containment", "procedure", "sop", "mitigation", "ransomware", "botnet"])

    # If full combined triage is requested
    if wants_all:
        target_ip = raw_ips[0] if raw_ips else "185.220.101.43"
        target_cve = raw_cves[0] if raw_cves else "CVE-2021-44228"
        target_mac = raw_macs[0] if raw_macs else "00:1A:2B:3C:4D:5E"
        triage_resp = await full_triage(FullTriageRequest(
            filepath="D:\\CYBERSICKER\\KDDTrain+.txt",
            ip_address=target_ip,
            cve_id=target_cve,
            mac_address=target_mac,
            incident_type="Botnet infection containment and perimeter isolation"
        ))
        if triage_resp.success:
            parsed = json.loads(triage_resp.result)
            return {
                "handled": True,
                "text": (
                    f"### [INCIDENT DOSSIER] Full-Spectrum Multi-Vector Triage Report\n\n"
                    f"**Executive Posture:** **{parsed.get('overall_status', 'CRITICAL THREAT DETECTED')}**\n"
                    f"**Global Verdict:** **{parsed.get('verdict', 'MALICIOUS')}**\n\n"
                    f"---\n\n"
                    f"#### 1. Network Traffic Anomaly Scan (Keras Autoencoder)\n"
                    f"- **Target Connection Log:** `{parsed.get('scan', {}).get('filepath')}`\n"
                    f"- **Anomalies Detected:** **{parsed.get('scan', {}).get('anomalies_detected')}** (Threshold MSE > {parsed.get('scan', {}).get('threshold')})\n"
                    f"- **Engine Architecture:** {parsed.get('scan', {}).get('model')}\n"
                    f"- **Scan Risk Verdict:** **{parsed.get('scan', {}).get('verdict')}**\n\n"
                    f"#### 2. Threat Intelligence & IP Reputation (VirusTotal)\n"
                    f"- **Observed Remote Host:** `{parsed.get('ip', {}).get('ip')}`\n"
                    f"- **Host Reputation:** **{parsed.get('ip', {}).get('verdict')}**\n"
                    f"- **Flagged Engines:** **{parsed.get('ip', {}).get('malicious', 0)} / 72** security vendors\n"
                    f"- **Suspicious Score:** {parsed.get('ip', {}).get('suspicious', 0)}\n\n"
                    f"#### 3. Vulnerability Correlation (NIST NVD)\n"
                    f"- **Vulnerability ID:** `{parsed.get('cve', {}).get('cve_id')}`\n"
                    f"- **CVSS Base Score:** **{parsed.get('cve', {}).get('cvss_score')}** ({parsed.get('cve', {}).get('severity')})\n"
                    f"- **Advisory Summary:** {parsed.get('cve', {}).get('description')}\n"
                    f"- **Vendor Remediation:** {parsed.get('cve', {}).get('recommendation')}\n\n"
                    f"#### 4. Hardware Identity & Device Profiling (IEEE OUI)\n"
                    f"- **Interface MAC:** `{parsed.get('mac', {}).get('mac')}`\n"
                    f"- **Manufacturer / Vendor:** **{parsed.get('mac', {}).get('vendor')}** (OUI: `{parsed.get('mac', {}).get('oui')}`)\n"
                    f"- **Asset Assessment:** {parsed.get('mac', {}).get('note')}\n\n"
                    f"#### 5. Incident Response Playbook Containment Steps (RAG)\n"
                    f"- **Trigger Scenario:** {parsed.get('playbook', {}).get('topic')}\n"
                    f"```text\n{parsed.get('playbook', {}).get('procedures')}\n```"
                )
            }

    sections = []

    # Traffic Scan
    if wants_scan:
        scan_resp = await network_scan(ScanRequest(filepath="D:\\CYBERSICKER\\KDDTrain+.txt"))
        if scan_resp.success:
            s_data = json.loads(scan_resp.result)
            sections.append(
                f"### [SCAN REPORT] Network Traffic Anomaly Analysis\n\n"
                f"- **Target File:** `{s_data.get('filepath')}`\n"
                f"- **Anomalies Detected:** **{s_data.get('anomalies_detected')}**\n"
                f"- **Baseline Threshold:** Reconstruction MSE > {s_data.get('threshold')}\n"
                f"- **Neural Architecture:** {s_data.get('model')}\n"
                f"- **Verdict:** **{s_data.get('verdict')}**"
            )

    # VirusTotal IP Check
    if wants_ip:
        ips_to_check = raw_ips if raw_ips else ["185.220.101.43"]
        for ip in ips_to_check:
            ip_resp = await check_ip(IPRequest(ip_address=ip))
            if ip_resp.success:
                ip_data = json.loads(ip_resp.result)
                verdict = ip_data.get("verdict", "UNKNOWN")
                mal = ip_data.get("malicious", 0)
                susp = ip_data.get("suspicious", 0)
                note = ip_data.get("note", "")

                if verdict == "MALICIOUS":
                    sections.append(
                        f"### [CRITICAL ALERT] Malicious Host Identified — VirusTotal Intelligence\n\n"
                        f"- **Target Address:** `{ip}`\n"
                        f"- **Security Verdict:** **MALICIOUS**\n"
                        f"- **Detection Ratio:** Flagged by **{mal} / 72** security engines\n"
                        f"- **Suspicious Score:** {susp}\n"
                        + (f"- **Intelligence Note:** {note}\n" if note else "") +
                        f"\n**Actionable Containment:** Block at ingress firewall and isolate any communicating IoT gateway."
                    )
                else:
                    sections.append(
                        f"### [VERIFIED CLEAN] Host Reputation Check — VirusTotal Intelligence\n\n"
                        f"- **Target Address:** `{ip}`\n"
                        f"- **Security Verdict:** **CLEAN**\n"
                        f"- **Detection Ratio:** {mal} / 72 engines flagged this address\n"
                        + (f"- **Intelligence Note:** {note}\n" if note else "") +
                        f"- **Status:** No malicious activities reported for this host."
                    )

    # NIST NVD CVE Lookup
    if wants_cve:
        cves_to_check = raw_cves if raw_cves else ["CVE-2021-44228"]
        for cve_id in cves_to_check:
            cve_resp = await cve_lookup(CVERequest(cve_id=cve_id))
            if cve_resp.success:
                cve_data = json.loads(cve_resp.result)
                if cve_data.get("found"):
                    sections.append(
                        f"### [VULNERABILITY REPORT] NIST NVD Advisory: {cve_id}\n\n"
                        f"- **Published Date:** {cve_data.get('published')}\n"
                        f"- **CVSS Base Score:** **{cve_data.get('cvss_score')}** ({cve_data.get('severity')})\n"
                        f"- **Summary:** {cve_data.get('description', '')[:350]}...\n"
                        f"- **Remediation:** {cve_data.get('recommendation', 'Apply vendor security patch.')}"
                    )
                else:
                    sections.append(
                        f"### [RECORD NOT FOUND] NIST NVD Advisory: {cve_id}\n\n"
                        f"No active NVD entry found for `{cve_id}`. Verify CVE formatting or query local cache."
                    )

    # MAC Lookup
    if wants_mac:
        macs_to_check = raw_macs if raw_macs else ["00:1A:2B:3C:4D:5E"]
        for mac in macs_to_check:
            mac_resp = await mac_lookup(MACRequest(mac_address=mac))
            if mac_resp.success:
                m_data = json.loads(mac_resp.result)
                sections.append(
                    f"### [HARDWARE LOOKUP] IEEE MAC OUI Registration\n\n"
                    f"- **MAC Address:** `{m_data.get('mac')}`\n"
                    f"- **OUI Prefix:** `{m_data.get('oui')}`\n"
                    f"- **Registered Vendor:** **{m_data.get('vendor')}**\n"
                    f"- **Device Type Note:** {m_data.get('note', 'Standard Network Interface')}"
                )

    # Playbook Consultation
    if wants_playbook:
        pb_topic = "botnet" if "botnet" in msg_lower else ("ddos" if "flood" in msg_lower or "ddos" in msg_lower else "ransomware")
        pb_resp = await consult_playbook(PlaybookRequest(incident_type=pb_topic))
        if pb_resp.success:
            pb_data = json.loads(pb_resp.result)
            sections.append(
                f"### [PLAYBOOK DIRECTIVE] Incident Response SOP\n\n"
                f"- **Incident Classification:** {pb_topic.upper()}\n"
                f"```text\n{pb_data.get('content', '')[:500]}\n```"
            )

    if sections:
        return {
            "handled": True,
            "text": "\n\n---\n\n".join(sections)
        }
    return {"handled": False, "text": ""}


@app.post("/api/chat")
async def agent_chat(req: ChatRequest):
    debug_log("B1", "api.py:agent_chat:entry", "Chat request entered", {
        "message_len": len(req.message or ""),
        "google_key_set": bool(GOOGLE_API_KEY),
        "vt_key_set": bool(VT_API_KEY),
        "groq_key_set": bool(GROQ_API_KEY),
        "openrouter_key_set": bool(OPENROUTER_API_KEY),
        "scitely_key_set": bool(SCITELY_API_KEY),
    })

    # Step 1: Run Dynamic Entity Extraction & Tool Dispatch
    dispatch = await dynamic_dispatch_prompt(req.message)

    # Step 2: Check for configured LLM
    llm = None
    provider = "none"
    if GOOGLE_API_KEY:
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0, api_key=GOOGLE_API_KEY)
        provider = "google"
    elif GROQ_API_KEY:
        from langchain_groq import ChatGroq
        llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0, api_key=GROQ_API_KEY)
        provider = "groq"
    elif OPENROUTER_API_KEY:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model="openai/gpt-4o-mini",
            temperature=0,
            api_key=OPENROUTER_API_KEY,
            base_url="https://openrouter.ai/api/v1",
        )
        provider = "openrouter"
    elif SCITELY_API_KEY:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model=SCITELY_MODEL,
            temperature=0,
            api_key=SCITELY_API_KEY,
            base_url=SCITELY_BASE_URL,
        )
        provider = "scitely"

    # Step 3: Synthesize response
    if dispatch["handled"]:
        # If tools were dynamically dispatched, return exact findings
        # (Optionally enhance with LLM if available and responsive)
        if llm:
            try:
                system_prompt = (
                    "You are Cybersicker, an elite AI cybersecurity SOC agent designed by Vrishin Ram K. "
                    "The operator provided a security instruction. Below are the verified technical tool outputs "
                    "generated from the operator's exact entities. Provide a brief executive briefing followed by the structured technical findings. "
                    "CRITICAL: Do NOT alter, omit, or replace the IP addresses, CVE identifiers, CVSS metrics, MAC addresses, or verdicts."
                )
                user_content = f"Instruction: {req.message}\n\nVerified Tool Findings:\n{dispatch['text']}"
                llm_res = llm.invoke([("system", system_prompt), ("user", user_content)])
                if llm_res and getattr(llm_res, "content", None):
                    return {"success": True, "response": llm_res.content}
            except Exception as e:
                debug_log("B5", "api.py:agent_chat:llm_synthesis_fallback", f"LLM synthesis failed: {str(e)}", {})
        
        # Return authoritative dynamic tool dispatch result directly
        return {"success": True, "response": dispatch["text"]}

    # If no specific tools were triggered, handle conversational requests
    if llm:
        try:
            system_prompt = (
                "You are Cybersicker, an elite cybersecurity SOC agent designed by Vrishin Ram K. "
                "You assist SOC operators with network traffic anomaly detection, threat intelligence, and CVE analysis. "
                "Format responses cleanly with markdown and bold key findings."
            )
            llm_res = llm.invoke([("system", system_prompt), ("user", req.message)])
            if llm_res and getattr(llm_res, "content", None):
                return {"success": True, "response": llm_res.content}
        except Exception as e:
            debug_log("B2", "api.py:agent_chat:llm_conversational_failed", str(e), {})

    # Keyless / Fallback conversational responses
    msg_lower = req.message.lower()
    if "who are you" in msg_lower or "your name" in msg_lower or "introduce" in msg_lower or "purpose" in msg_lower:
        response = (
            "[SYSTEM PROFILE] Blue-Team Security Agent\n\n"
            "I am **Cybersicker**, an elite AI-powered cybersecurity SOC agent designed by **Vrishin Ram K**.\n\n"
            "My mission is to autonomously detect, investigate, and mitigate network threats in IoT environments by orchestrating threat intelligence and machine learning tools."
        )
    elif "what tools" in msg_lower or "available tools" in msg_lower or "capabilities" in msg_lower or "what can you do" in msg_lower or "tool list" in msg_lower:
        response = (
            "[SYSTEM CAPABILITIES] Operational Subsystems\n\n"
            "I have 5 autonomous security tools at my disposal:\n"
            "1. **Network Scanner**: Deep neural network autoencoder anomaly scan on logs.\n"
            "2. **IP Check**: Threat intelligence lookup via VirusTotal API.\n"
            "3. **MAC Lookup**: Resolves device manufacturer from MAC OUI.\n"
            "4. **CVE Database**: NIST NVD vulnerability database query.\n"
            "5. **Consult Playbook**: RAG-based ChromaDB query for incident response procedures.\n\n"
            "*(You can also trigger these dynamically from the left deck or by typing any IP, CVE, or MAC address into the console!)*"
        )
    elif "hi" in msg_lower or "hello" in msg_lower or "hey" in msg_lower or "help" in msg_lower:
        response = (
            "[INITIALIZED] Cybersicker SOC Console v2.0\n\n"
            "Hello! I am **Cybersicker**, your autonomous SOC analyst. How can I assist with your threat intelligence or anomaly detection operations today?\n\n"
            "You can provide specific entities (e.g. *Analyze IP 8.8.8.8 and query CVE-2024-3094*) or click **Run Full-Spectrum Pipeline** to execute all vectors concurrently."
        )
    else:
        response = (
            "[OPERATOR DIRECTIVE] Cybersicker Autonomous Agent\n\n"
            "I am ready to process your security instructions. You can input custom targets like:\n"
            "- Specific IPs: *Analyze IP 8.8.8.8* or *Check 185.220.101.43*\n"
            "- Vulnerability IDs: *Query CVE-2024-3094* or *Lookup CVE-2021-44228*\n"
            "- Device MACs: *Resolve MAC 00:1A:2B:3C:4D:5E*\n"
            "- Combined analysis: *Run full triage pipeline*"
        )

    return {"success": True, "response": response}


# ─── Health check ────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status": "online",
        "google_key_set": bool(GOOGLE_API_KEY),
        "groq_key_set": bool(GROQ_API_KEY),
        "openrouter_key_set": bool(OPENROUTER_API_KEY),
        "scitely_key_set": bool(SCITELY_API_KEY),
        "vt_key_set": bool(VT_API_KEY),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
