"""
CYBERSICKER — Unified Security Tools
Shared tool definitions for Agent CLI, Streamlit Dashboard, and FastAPI Backend.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

import requests
from langchain.tools import tool

from autoencoder import run_network_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Cybersicker.Tools")

BASE_DIR = Path(__file__).resolve().parent
PLAYBOOK_PATH = BASE_DIR / "playbook.env.txt"


def sanitize_input(user_input: str, max_length: int = 1000) -> tuple[str, bool]:
    """Sanitize user input against prompt injection patterns."""
    if not user_input or len(user_input) == 0:
        return "", False
    if len(user_input) > max_length:
        return "", False

    sanitized = user_input.strip()
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
    """Escape HTML special characters for safe frontend rendering."""
    return html.escape(str(text))


@tool
def network_scanner(filepath: str) -> str:
    """
    Scan network traffic logs for cyber attacks and anomalies using ML-based detection.
    
    Args:
        filepath: Path to network traffic CSV or KDDTrain+.txt
    """
    logger.info("Scanning %s for network anomalies...", filepath)
    try:
        anomalies = run_network_scan(filepath)
        if isinstance(anomalies, str) and "Error" in anomalies:
            return anomalies

        if int(anomalies) > 100:
            risk_level = "CRITICAL"
        elif int(anomalies) > 50:
            risk_level = "HIGH"
        elif int(anomalies) > 20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return (
            f"Scan complete. Found {anomalies} anomalies ({risk_level}). "
            f"MITRE ATT&CK Coverage: T1571, T1008, T1498, T1570, T1041. "
            f"NIST CSF: DE.CM-01, DE.AE-02."
        )
    except Exception as e:
        logger.error("Scan failed: %s", e, exc_info=True)
        return f"Failed to run scanner: {e}"


@tool
def check_ip_virustotal(ip_address: str) -> str:
    """
    Investigate an IP address using VirusTotal threat intelligence and reputation scoring.
    
    Args:
        ip_address: IPv4 address to investigate
    """
    ip_parts = ip_address.strip().split(".")
    if len(ip_parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
        return f"[Error] Invalid IPv4 format: {ip_address}"

    vt_key = os.environ.get("VT_API_KEY", "")
    if not vt_key:
        return f"[Notice] VirusTotal API key not configured. Mocking lookup for IP: {ip_address} (Safe/Unknown)."

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address.strip()}"
    headers = {"accept": "application/json", "x-apikey": vt_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 401:
            return "[Error] VirusTotal API authentication failed (Invalid API key)."
        if response.status_code == 404:
            return f"[Info] IP {ip_address} not found in VirusTotal database (likely new/clean)."
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)

            total_votes = malicious + suspicious + undetected
            reputation_score = 100 if total_votes == 0 else max(0, 100 - (malicious * 10 + suspicious * 3))

            if malicious > 5:
                threat_level, action = "CRITICAL", "BLOCK IMMEDIATELY"
            elif malicious > 0:
                threat_level, action = "HIGH", "QUARANTINE & INVESTIGATE"
            elif suspicious > 3:
                threat_level, action = "MEDIUM", "MONITOR CLOSELY"
            else:
                threat_level, action = "LOW", "ALLOW"

            asn_info = data.get("data", {}).get("attributes", {}).get("asn", {}).get("asn", "Unknown")
            country = data.get("data", {}).get("attributes", {}).get("country", "Unknown")

            return (
                f"[THREAT INTELLIGENCE] IP: {ip_address}\n"
                f"Threat Level: {threat_level}\n"
                f"Reputation Score: {reputation_score}/100\n"
                f"Vendors Malicious: {malicious} | Suspicious: {suspicious} | Clean: {undetected}\n"
                f"ASN: {asn_info} | Country: {country}\n"
                f"Recommendation: {action}\n"
                f"MITRE ATT&CK: T1592 | NIST CSF: DE.CM-01"
            )
        return f"[Error] VirusTotal API returned status {response.status_code}"
    except Exception as e:
        logger.error("VirusTotal query failed: %s", e, exc_info=True)
        return f"[Error] Could not query VirusTotal: {e}"


@tool
def lookup_mac_address(mac_address: str) -> str:
    """
    Look up the manufacturer/vendor of a network device by its MAC address.
    
    Args:
        mac_address: MAC address formatted as AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
    """
    clean_mac = mac_address.replace("-", ":").strip()
    oui = clean_mac.replace(":", "")[:6].upper()
    url = f"https://api.macvendors.com/{clean_mac}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            vendor = response.text.strip()
            return (
                f"MAC Address: {clean_mac}\n"
                f"OUI Prefix: {oui}\n"
                f"Device Manufacturer: {vendor}\n"
                f"Recommendation: Cross-reference '{vendor}' against authorized IoT asset registry."
            )
        elif response.status_code == 404:
            return f"MAC {clean_mac} (OUI: {oui}) — Vendor NOT FOUND. Potential spoofed MAC or unlisted vendor. Treat as suspicious."
        return f"MAC lookup failed with status code {response.status_code}."
    except Exception as e:
        return f"Error looking up MAC address: {e}"


@tool
def query_cve_database(cve_id: str) -> str:
    """
    Query the NIST National Vulnerability Database (NVD) for CVE details, CVSS score, and remediation.
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2021-44228)
    """
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        return f"[Error] Invalid CVE ID format: '{cve_id}'. Expected format 'CVE-YYYY-NNNN'."

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return f"CVE {cve_id} not found in the NIST NVD database."
            cve_data = vulns[0].get("cve", {})
            desc_list = cve_data.get("descriptions", [])
            description = next((d["value"] for d in desc_list if d.get("lang") == "en"), "No description available.")
            metrics = cve_data.get("metrics", {})
            cvss_score = "N/A"
            severity = "N/A"
            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version_key in metrics and metrics[version_key]:
                    cvss_data = metrics[version_key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", "N/A")
                    break
            published = cve_data.get("published", "Unknown")[:10]
            return (
                f"CVE ID: {cve_id}\n"
                f"Published: {published}\n"
                f"CVSS Score: {cvss_score} ({severity})\n"
                f"Description: {description[:400]}\n"
                f"Recommendation: Patch immediately if score >= 7.0 (High/Critical). Check vendor security advisories."
            )
        elif response.status_code == 403:
            return "NIST NVD API rate limited. Please retry in 30 seconds."
        return f"NVD API returned status code {response.status_code}."
    except Exception as e:
        return f"Error querying CVE database: {e}"


@tool
def consult_playbook(incident_type: str) -> str:
    """
    Consult the incident response playbook for structured containment and recovery procedures.
    
    Args:
        incident_type: Description of incident (e.g., "ransomware", "ddos", "iot anomalies")
    """
    playbook_file = PLAYBOOK_PATH if PLAYBOOK_PATH.exists() else BASE_DIR / "playbook.txt"
    if not playbook_file.exists():
        return "[Warning] Incident response playbook file not found on system."

    try:
        content = playbook_file.read_text(encoding="utf-8", errors="ignore")
        paragraphs = [p.strip() for p in content.split("\n\n") if p.strip()]
        
        # Keyword matching fallback without heavyweight vectorstore dependency
        matches = [p for p in paragraphs if any(k.lower() in p.lower() for k in incident_type.split())]
        if not matches:
            matches = paragraphs[:3]

        selected = "\n---\n".join(matches[:3])
        return (
            f"[INCIDENT RESPONSE PLAYBOOK] Topic: {incident_type}\n\n"
            f"{selected}\n\n"
            f"[ACTION ITEMS]\n"
            f"1. Isolate affected network segment / IoT devices\n"
            f"2. Capture memory and network flow logs for forensic analysis\n"
            f"3. Escalate to SOC lead and implement remediation\n"
            f"4. Verify containment and restore from known-good baseline"
        )
    except Exception as e:
        return f"Error reading playbook: {e}"


ALL_TOOLS = [
    network_scanner,
    check_ip_virustotal,
    lookup_mac_address,
    query_cve_database,
    consult_playbook,
]
