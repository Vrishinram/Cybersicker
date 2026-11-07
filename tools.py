"""
CYBERSICKER — Unified Security Tools
Shared tool definitions for Agent CLI, Streamlit Dashboard, and FastAPI Backend.
Hardened with indirect prompt injection defenses, timeouts, and rate limiters.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict

import requests
from langchain.tools import tool

from autoencoder import run_network_scan

try:
    from app.services.nvd import CURATED_CVE_CATALOG
except ImportError:
    CURATED_CVE_CATALOG = {
        "CVE-2024-3094": {
            "published": "2024-03-29",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "description": "Malicious code discovered in upstream tarballs of xz-utils (liblzma versions 5.6.0 and 5.6.1) that intercepts OpenSSH sshd process authentication to allow unauthorized remote execution.",
            "recommendation": "Immediately downgrade xz-utils to 5.4.6 or earlier; inspect all active sshd processes, and revoke compromised SSH host keys."
        },
        "CVE-2021-44228": {
            "published": "2021-12-10",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "description": "Apache Log4j2 versions 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker-controlled LDAP/JNDI endpoints (Log4Shell).",
            "recommendation": "Upgrade to Apache Log4j 2.17.1 or higher immediately."
        }
    }

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Cybersicker.Tools")

BASE_DIR = Path(__file__).resolve().parent
PLAYBOOK_PATH = BASE_DIR / "playbook.env.txt"

# Rate limit tracking: {tool_name: last_called_timestamp}
_LAST_CALL_TIMES: Dict[str, float] = {}
RATE_LIMIT_COOLDOWN_SECONDS = 1.0  # Minimum delay between outbound API calls


def _apply_rate_limit(tool_name: str) -> None:
    """Enforce a minimum cooldown between rapid external API calls."""
    now = time.time()
    last_called = _LAST_CALL_TIMES.get(tool_name, 0.0)
    elapsed = now - last_called
    if elapsed < RATE_LIMIT_COOLDOWN_SECONDS:
        time.sleep(RATE_LIMIT_COOLDOWN_SECONDS - elapsed)
    _LAST_CALL_TIMES[tool_name] = time.time()


def sanitize_input(user_input: str, max_length: int = 1000) -> tuple[str, bool]:
    """Sanitize user input against direct prompt injection patterns."""
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
        r"you\s+are\s+now\s+DAN",
        r"developer\s+mode",
    ]
    for pattern in injection_patterns:
        if re.search(pattern, sanitized, re.IGNORECASE):
            return "", False
    return sanitized, True


def sanitize_tool_output(tool_output: str) -> str:
    """
    Treat tool outputs as untrusted third-party content.
    Scan and defang any indirect prompt injection attempts or system delimiter tokens.
    """
    if not tool_output:
        return ""

    # Neutralize dangerous instruction tags and delimiters
    defanged = tool_output
    dangerous_delimiters = [
        ("</system>", "[DEFANGED_SYSTEM_TAG]"),
        ("<system>", "[DEFANGED_SYSTEM_TAG]"),
        ("<|im_start|>", "[DEFANGED_TOKEN]"),
        ("<|im_end|>", "[DEFANGED_TOKEN]"),
        ("[INST]", "[DEFANGED_INST]"),
        ("[/INST]", "[DEFANGED_INST]"),
        ("<<SYS>>", "[DEFANGED_SYS]"),
        ("<|system|>", "[DEFANGED_SYS]"),
    ]
    for raw_tag, safe_tag in dangerous_delimiters:
        defanged = defanged.replace(raw_tag, safe_tag)

    # Detect indirect injection phrases inside API responses
    indirect_injection_regexes = [
        re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts)"),
        re.compile(r"(?i)system\s+override\s+code"),
        re.compile(r"(?i)disregard\s+all\s+safety"),
    ]
    for rx in indirect_injection_regexes:
        defanged = rx.sub("[SUSPICIOUS_INDIRECT_INJECTION_STRIPPED]", defanged)

    return defanged


def escape_output(text: str) -> str:
    """Escape HTML special characters for safe frontend rendering."""
    return html.escape(str(text))


@tool
def network_scanner(filepath: str) -> str:
    """
    Scan network traffic logs for cyber attacks and anomalies using ML-based detection.
    
    Args:
        filepath: Path to network traffic CSV or KDDTrain+.txt in sandboxed directory
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

        raw_result = (
            f"Scan complete. Found {anomalies} anomalies ({risk_level}). "
            f"MITRE ATT&CK Coverage: T1571, T1008, T1498, T1570, T1041. "
            f"NIST CSF: DE.CM-01, DE.AE-02."
        )
        return sanitize_tool_output(raw_result)
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

    _apply_rate_limit("virustotal")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address.strip()}"
    headers = {"accept": "application/json", "x-apikey": vt_key}

    try:
        response = requests.get(url, headers=headers, timeout=8)
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

            raw_report = (
                f"[THREAT INTELLIGENCE] IP: {ip_address}\n"
                f"Threat Level: {threat_level}\n"
                f"Reputation Score: {reputation_score}/100\n"
                f"Vendors Malicious: {malicious} | Suspicious: {suspicious} | Clean: {undetected}\n"
                f"ASN: {asn_info} | Country: {country}\n"
                f"Recommendation: {action}\n"
                f"MITRE ATT&CK: T1592 | NIST CSF: DE.CM-01"
            )
            return sanitize_tool_output(raw_report)
        return f"[Error] VirusTotal API returned status {response.status_code}"
    except requests.Timeout:
        return "[Error] VirusTotal request timed out after 8s."
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

    _apply_rate_limit("macvendors")
    url = f"https://api.macvendors.com/{clean_mac}"
    try:
        response = requests.get(url, timeout=6)
        if response.status_code == 200:
            vendor = sanitize_tool_output(response.text.strip())
            return (
                f"MAC Address: {clean_mac}\n"
                f"OUI Prefix: {oui}\n"
                f"Device Manufacturer: {vendor}\n"
                f"Recommendation: Cross-reference '{vendor}' against authorized IoT asset registry."
            )
        elif response.status_code == 404:
            return f"MAC {clean_mac} (OUI: {oui}) — Vendor NOT FOUND. Potential spoofed MAC or unlisted vendor. Treat as suspicious."
        return f"MAC lookup failed with status code {response.status_code}."
    except requests.Timeout:
        return "[Error] MAC vendor lookup timed out after 6s."
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

    _apply_rate_limit("nvd")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
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
            
            clean_desc = sanitize_tool_output(description[:400])
            return (
                f"CVE ID: {cve_id}\n"
                f"Published: {published}\n"
                f"CVSS Score: {cvss_score} ({severity})\n"
                f"Description: {clean_desc}\n"
                f"Recommendation: Patch immediately if score >= 7.0 (High/Critical). Check vendor security advisories."
            )
        elif response.status_code in (403, 429):
            if cve_id in CURATED_CVE_CATALOG:
                cached = CURATED_CVE_CATALOG[cve_id]
                return (
                    f"CVE ID: {cve_id}\n"
                    f"Published: {cached['published']}\n"
                    f"CVSS Score: {cached['cvss_score']} ({cached['severity']})\n"
                    f"Description: {cached['description']}\n"
                    f"Recommendation: {cached['recommendation']}"
                )
            return "NIST NVD API rate limited. Please retry in 30 seconds."
        return f"NVD API returned status code {response.status_code}."
    except (requests.Timeout, Exception) as e:
        if cve_id in CURATED_CVE_CATALOG:
            cached = CURATED_CVE_CATALOG[cve_id]
            return (
                f"CVE ID: {cve_id}\n"
                f"Published: {cached['published']}\n"
                f"CVSS Score: {cached['cvss_score']} ({cached['severity']})\n"
                f"Description: {cached['description']}\n"
                f"Recommendation: {cached['recommendation']}"
            )
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
        
        matches = [p for p in paragraphs if any(k.lower() in p.lower() for k in incident_type.split())]
        if not matches:
            matches = paragraphs[:3]

        selected = "\n---\n".join(matches[:3])
        clean_selected = sanitize_tool_output(selected)
        return (
            f"[INCIDENT RESPONSE PLAYBOOK] Topic: {incident_type}\n\n"
            f"{clean_selected}\n\n"
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
