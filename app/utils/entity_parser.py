"""
CYBERSICKER — Dynamic Entity Extraction & Strict RFC 791 Validation Module
Provides zero-fallback entity parsing, IEEE OUI identification, and telemetry event generation.
"""

import re
import ipaddress
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# ═══════════════════════════════════════════════════════════════
# EXCEPTIONS & MODELS
# ═══════════════════════════════════════════════════════════════

class EntityValidationError(Exception):
    """Raised when an input entity violates RFC specifications (e.g. malformed IPv4 octet)."""
    def __init__(self, message: str, invalid_value: str, specification: str = "RFC 791"):
        super().__init__(message)
        self.message = message
        self.invalid_value = invalid_value
        self.specification = specification


class ParsedEntities(BaseModel):
    raw_prompt: str
    ips: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)
    macs: List[str] = Field(default_factory=list)
    intents: List[str] = Field(default_factory=list)
    has_scan_intent: bool = False
    has_playbook_intent: bool = False
    has_full_pipeline_intent: bool = False
    playbook_query: Optional[str] = None
    telemetry_event: Optional[Dict[str, Any]] = None


# ═══════════════════════════════════════════════════════════════
# REGEX DEFINITIONS
# ═══════════════════════════════════════════════════════════════

# Candidate IPv4 regex (captures 4 dotted decimal groups to enable strict boundary validation)
CANDIDATE_IPV4_REGEX = re.compile(r'\b(?:\d{1,4}\.){3}\d{1,4}\b')

# Standard CVE syntax (case-insensitive)
CVE_REGEX = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

# MAC address regex (supports colons, hyphens, and Cisco dot notation)
MAC_COLON_HYPHEN_REGEX = re.compile(r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})')
MAC_CISCO_DOT_REGEX = re.compile(r'\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b')


# ═══════════════════════════════════════════════════════════════
# IEEE OUI VENDOR REGISTRY
# ═══════════════════════════════════════════════════════════════

IEEE_OUI_DATABASE: Dict[str, Dict[str, str]] = {
    # Raspberry Pi Foundation (IoT Single Board Computer)
    "B827EB": {
        "vendor": "Raspberry Pi Foundation",
        "device_note": "Identified low-cost IoT single-board computer; inspect unauthorized local network presence.",
        "category": "IoT Single Board Computer"
    },
    "DCA632": {
        "vendor": "Raspberry Pi Foundation",
        "device_note": "Identified Raspberry Pi IoT node; check for default credentials and exposed management interfaces.",
        "category": "IoT Single Board Computer"
    },
    "E45F01": {
        "vendor": "Raspberry Pi Foundation",
        "device_note": "Identified Raspberry Pi 4/5 compute module; monitor for lateral traffic or shadow IoT presence.",
        "category": "IoT Single Board Computer"
    },
    "28CDC1": {
        "vendor": "Raspberry Pi Foundation",
        "device_note": "Identified Raspberry Pi Foundation endpoint.",
        "category": "IoT Single Board Computer"
    },

    # Google LLC (Smart Device / Nest / Infrastructure)
    "001A11": {
        "vendor": "Google LLC",
        "device_note": "Identified smart home/Nest or Google hardware endpoint; inspect IoT perimeter isolation rules.",
        "category": "Smart Device / Nest"
    },
    "F4F5D8": {
        "vendor": "Google LLC",
        "device_note": "Identified Google Nest smart hub or Chromecast controller; isolate on dedicated IoT VLAN.",
        "category": "Smart Device / Nest"
    },
    "D86C63": {
        "vendor": "Google LLC",
        "device_note": "Identified Google edge device or consumer IoT appliance.",
        "category": "Smart Device / Nest"
    },

    # Espressif Systems (ESP32 / ESP8266 Microcontroller)
    "FC65DE": {
        "vendor": "Espressif Systems",
        "device_note": "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.",
        "category": "IoT Microcontroller"
    },
    "240AC4": {
        "vendor": "Espressif Systems",
        "device_note": "Identified Espressif ESP32 Wi-Fi SoC; inspect for plaintext telemetry or hardcoded C2 endpoints.",
        "category": "IoT Microcontroller"
    },
    "30AEA4": {
        "vendor": "Espressif Systems",
        "device_note": "Identified Espressif IoT sensor node or smart actuator.",
        "category": "IoT Microcontroller"
    },
    "A4CF12": {
        "vendor": "Espressif Systems",
        "device_note": "Identified Espressif Systems microcontroller.",
        "category": "IoT Microcontroller"
    },

    # VMware, Inc. (Virtual Machine Interface)
    "000C29": {
        "vendor": "VMware, Inc.",
        "device_note": "Identified VMware ESXi/Workstation virtual network adapter; confirm virtualization host legitimacy.",
        "category": "Virtual Machine Interface"
    },
    "005056": {
        "vendor": "VMware, Inc.",
        "device_note": "Identified VMware ESXi/vSphere enterprise virtual network interface.",
        "category": "Virtual Machine Interface"
    },
    "000569": {
        "vendor": "VMware, Inc.",
        "device_note": "Identified VMware legacy virtual adapter.",
        "category": "Virtual Machine Interface"
    },

    # Parallels, Inc.
    "001C42": {
        "vendor": "Parallels, Inc.",
        "device_note": "Identified Parallels desktop virtualization guest adapter.",
        "category": "Virtual Machine Interface"
    },

    # Microsoft Corporation
    "00155D": {
        "vendor": "Microsoft Corporation",
        "device_note": "Identified Microsoft Hyper-V virtual network interface or Windows endpoint.",
        "category": "Virtual Machine Interface"
    },

    # Cisco Systems, Inc.
    "001A2B": {
        "vendor": "Cisco Systems, Inc.",
        "device_note": "Verified enterprise switch, router, or core network infrastructure gateway.",
        "category": "Enterprise Gateway"
    },
    "00000C": {
        "vendor": "Cisco Systems, Inc.",
        "device_note": "Verified Cisco Systems core networking hardware interface.",
        "category": "Enterprise Gateway"
    },
    "000142": {
        "vendor": "Cisco Systems, Inc.",
        "device_note": "Verified Cisco Systems network equipment.",
        "category": "Enterprise Gateway"
    },

    # Apple, Inc.
    "3C5AB4": {
        "vendor": "Apple, Inc.",
        "device_note": "Identified Apple macOS/iOS endpoint; verify corporate MDM profile.",
        "category": "Workstation / Mobile"
    },
    "ACBC32": {
        "vendor": "Apple, Inc.",
        "device_note": "Identified Apple Inc. network interface.",
        "category": "Workstation / Mobile"
    },
}


# ═══════════════════════════════════════════════════════════════
# EXTRACTION & VALIDATION LOGIC
# ═══════════════════════════════════════════════════════════════

def normalize_mac(raw_mac: str) -> tuple[str, str]:
    """
    Cleans separators from MAC address and extracts the 6-hex-character OUI prefix.
    Returns (normalized_mac, oui_prefix).
    """
    clean = re.sub(r'[^0-9A-Fa-f]', '', raw_mac).upper()
    if len(clean) < 6:
        return raw_mac, clean
    
    oui = clean[:6]
    formatted = ":".join(clean[i:i+2] for i in range(0, min(12, len(clean)), 2))
    return formatted, oui


def lookup_oui(mac_address: str) -> Dict[str, str]:
    """
    Resolves MAC address against authentic IEEE OUI database and detects locally administered addresses.
    """
    formatted_mac, oui = normalize_mac(mac_address)
    
    if len(oui) < 6:
        return {
            "mac": mac_address,
            "oui": oui,
            "vendor": "INVALID_MAC",
            "device_note": "Malformed MAC address: fewer than 6 hexadecimal characters.",
            "category": "Invalid"
        }

    # 1. Match against known authentic IEEE OUI database
    if oui in IEEE_OUI_DATABASE:
        data = IEEE_OUI_DATABASE[oui]
        return {
            "mac": formatted_mac,
            "oui": oui,
            "vendor": data["vendor"],
            "device_note": data["device_note"],
            "category": data["category"]
        }

    # 2. Check for Locally Administered Address (LAA / Randomized MAC)
    # The second least-significant bit of the first byte indicates LAA (e.g. x2, x6, xA, xE)
    try:
        first_byte = int(oui[:2], 16)
        is_laa = bool(first_byte & 0x02)
    except Exception:
        is_laa = False

    if is_laa or oui == "AABBCC":
        return {
            "mac": formatted_mac,
            "oui": oui,
            "vendor": "Locally Administered / Private Unregistered MAC",
            "device_note": "Locally administered address (LAA) or randomized/spoofed MAC; treat as high-risk untrusted endpoint.",
            "category": "Randomized / Spoofed"
        }

    # 3. Unmatched IEEE prefix
    return {
        "mac": formatted_mac,
        "oui": oui,
        "vendor": "Unknown / Private MAC",
        "device_note": "Unregistered hardware vendor in local cache; monitor device telemetry for abnormal egress traffic.",
        "category": "Unknown / Unregistered"
    }


def parse_and_validate_entities(prompt: str) -> ParsedEntities:
    """
    Strictly extracts and validates IPv4 addresses (RFC 791), CVEs, and MAC addresses.
    Raises EntityValidationError on malformed octets instead of silent fallback.
    """
    raw_prompt = prompt or ""
    msg_lower = raw_prompt.lower()

    # ── 1. Strict RFC 791 IPv4 Extraction & Validation ──
    validated_ips: List[str] = []
    candidates = CANDIDATE_IPV4_REGEX.findall(raw_prompt)

    for cand in candidates:
        try:
            ip_obj = ipaddress.ip_address(cand)
            if not isinstance(ip_obj, ipaddress.IPv4Address):
                raise ValueError("Not IPv4")
            validated_ips.append(str(ip_obj))
        except ValueError:
            raise EntityValidationError(
                message=f"[VALIDATION ERROR] Malformed IPv4 address: '{cand}'. "
                        f"Octets must be numeric integers strictly between 0 and 255 (RFC 791).",
                invalid_value=cand,
                specification="RFC 791"
            )

    # ── 2. CVE Extraction ──
    cves = [c.upper() for c in CVE_REGEX.findall(raw_prompt)]

    # ── 3. MAC OUI Extraction ──
    raw_macs: List[str] = []
    raw_macs.extend(MAC_COLON_HYPHEN_REGEX.findall(raw_prompt))
    raw_macs.extend(MAC_CISCO_DOT_REGEX.findall(raw_prompt))
    
    # Deduplicate while preserving order
    seen_macs = set()
    cleaned_macs = []
    for m in raw_macs:
        formatted, _ = normalize_mac(m)
        if formatted not in seen_macs:
            seen_macs.add(formatted)
            cleaned_macs.append(formatted)

    # ── 4. Multi-Intent Classification ──
    intents: List[str] = []
    has_full_pipeline = any(k in msg_lower for k in [
        "combine", "all tools", "full triage", "full-spectrum", "pipeline", "all vectors", "everything"
    ])
    has_scan = any(k in msg_lower for k in [
        "scan", "autoencoder", "kdd", "anomaly", "anomalies", "traffic log", "packet", "pcap"
    ])
    has_playbook = any(k in msg_lower for k in [
        "playbook", "sop", "mitigat", "containment", "procedure", "runbook", "syn flood",
        "arp spoof", "ransomware", "ddos", "botnet", "incident response"
    ])
    has_ip = len(validated_ips) > 0 or any(k in msg_lower for k in ["ip", "virustotal", "reputation", "host"])
    has_cve = len(cves) > 0 or any(k in msg_lower for k in ["cve", "vulnerability", "nist", "nvd", "exploit"])
    has_mac = len(cleaned_macs) > 0 or any(k in msg_lower for k in ["mac", "oui", "hardware", "manufacturer", "device"])

    if has_full_pipeline:
        intents.append("full_triage")
    if has_scan:
        intents.append("traffic_scan")
    if has_ip:
        intents.append("ip_reputation")
    if has_cve:
        intents.append("cve_lookup")
    if has_mac:
        intents.append("mac_resolution")
    if has_playbook:
        intents.append("playbook_rag")

    # Generate telemetry event
    extracted_types = []
    if validated_ips:
        extracted_types.append("ipv4")
    if cves:
        extracted_types.append("cve")
    if cleaned_macs:
        extracted_types.append("mac")

    telemetry = {
        "event": "DYNAMIC_ENTITY_EXTRACTED",
        "types": extracted_types,
        "values": {
            **({"ip": validated_ips[0]} if len(validated_ips) == 1 else ({"ips": validated_ips} if validated_ips else {})),
            **({"cve": cves[0]} if len(cves) == 1 else ({"cves": cves} if cves else {})),
            **({"mac": cleaned_macs[0]} if len(cleaned_macs) == 1 else ({"macs": cleaned_macs} if cleaned_macs else {})),
        }
    } if extracted_types else None

    # Derive playbook query topic
    playbook_query = None
    if has_playbook:
        for topic in ["syn flood", "arp spoof", "icmp flood", "ddos", "ransomware", "botnet", "c2", "log4j"]:
            if topic in msg_lower:
                playbook_query = topic
                break
        if not playbook_query:
            playbook_query = raw_prompt

    return ParsedEntities(
        raw_prompt=raw_prompt,
        ips=validated_ips,
        cves=cves,
        macs=cleaned_macs,
        intents=intents,
        has_scan_intent=has_scan,
        has_playbook_intent=has_playbook,
        has_full_pipeline_intent=has_full_pipeline,
        playbook_query=playbook_query,
        telemetry_event=telemetry
    )
