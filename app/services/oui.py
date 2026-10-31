"""
CYBERSICKER — Dynamic IEEE MAC OUI Resolution Service
Asynchronous OUI resolver combining a high-performance offline IEEE prefix table,
Locally Administered Address (LAA) bit analysis, and live macvendors API fallback.
"""

from __future__ import annotations

import re
import time
import logging
from typing import Dict, Any, Optional
import httpx

from app.services.telemetry import telemetry_service

logger = logging.getLogger("Cybersicker.OUI")

MACVENDORS_URL = "https://api.macvendors.com"
DEFAULT_TIMEOUT = 4.0

# Offline IEEE OUI Registry with categorized hardware profiles & security guidance
OFFLINE_OUI_DATABASE: Dict[str, Dict[str, str]] = {
    # Raspberry Pi Foundation (Single Board Computers / Embedded IoT)
    "B827EB": {
        "vendor": "Raspberry Pi Foundation",
        "category": "IoT Single-Board Computer",
        "device_note": "Identified low-cost IoT single-board computer; inspect unauthorized local network presence and verify default credential hardening.",
    },
    "DCA632": {
        "vendor": "Raspberry Pi Foundation",
        "category": "IoT Single-Board Computer",
        "device_note": "Identified Raspberry Pi 4/5 hardware. Audit USB peripherals and local network scanning services.",
    },
    "E45F01": {
        "vendor": "Raspberry Pi Foundation",
        "category": "IoT Single-Board Computer",
        "device_note": "Identified Raspberry Pi Compute Module or modern SBC interface. Verify inventory authorization.",
    },
    "28CDC1": {
        "vendor": "Raspberry Pi Foundation",
        "category": "IoT Single-Board Computer",
        "device_note": "Raspberry Pi Foundation hardware endpoint. Inspect ingress SSH and VNC listeners.",
    },

    # Espressif Systems (ESP8266 / ESP32 Microcontrollers)
    "FC65DE": {
        "vendor": "Espressif Systems",
        "category": "IoT Microcontroller",
        "device_note": "Identified low-power ESP32/ESP8266 microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.",
    },
    "240AC4": {
        "vendor": "Espressif Systems",
        "category": "IoT Microcontroller",
        "device_note": "Identified Espressif Wi-Fi chip. Audit wireless network access point and WPA2/WPA3 enterprise authentication.",
    },
    "30AEA4": {
        "vendor": "Espressif Systems",
        "category": "IoT Microcontroller",
        "device_note": "Identified ESP-WROOM IoT module. Isolate into IoT Guest VLAN to prevent lateral movement.",
    },
    "A4CF12": {
        "vendor": "Espressif Systems",
        "category": "IoT Microcontroller",
        "device_note": "Espressif Systems IoT SoC. Verify TLS encryption on all outbound telemetry streams.",
    },

    # Google LLC (Nest / Smart Display / Chromecast)
    "001A11": {
        "vendor": "Google LLC",
        "category": "Smart Device / Nest",
        "device_note": "Identified Google smart device / Nest hub; inspect IoT perimeter isolation rules and multicast mDNS traffic.",
    },
    "F4F5D8": {
        "vendor": "Google LLC",
        "category": "Smart Device / Nest",
        "device_note": "Google Nest audio/video endpoint. Confirm device authorization against enterprise IoT policy.",
    },
    "D86C63": {
        "vendor": "Google LLC",
        "category": "Smart Device / Nest",
        "device_note": "Google Chromecast or Nest Hub endpoint. Enforce strict isolation from sensitive corporate subnets.",
    },

    # VMware Inc. (Virtual Machine NICs)
    "000C29": {
        "vendor": "VMware, Inc.",
        "category": "Virtual Machine Interface",
        "device_note": "Identified VMware ESXi/Workstation virtual network adapter; confirm virtualization host legitimacy.",
    },
    "005056": {
        "vendor": "VMware, Inc.",
        "category": "Virtual Machine Interface",
        "device_note": "Identified VMware vSphere/vCenter managed vNIC. Audit vSwitch port groups and promiscuous mode settings.",
    },
    "000569": {
        "vendor": "VMware, Inc.",
        "category": "Virtual Machine Interface",
        "device_note": "VMware virtual interface. Cross-reference with vCenter VM inventory.",
    },

    # Microsoft Corporation (Hyper-V Virtual Adapter)
    "00155D": {
        "vendor": "Microsoft Corporation",
        "category": "Virtual Machine Interface",
        "device_note": "Identified Microsoft Hyper-V virtual network interface or Azure VM instance.",
    },

    # Parallels Inc. (Desktop Virtualization)
    "001C42": {
        "vendor": "Parallels, Inc.",
        "category": "Virtual Machine Interface",
        "device_note": "Identified Parallels Desktop macOS virtual guest adapter.",
    },

    # Cisco Systems Inc. (Enterprise Switch / Router / AP)
    "001A2B": {
        "vendor": "Cisco Systems, Inc.",
        "category": "Enterprise Gateway",
        "device_note": "Verified Cisco Catalyst switch, ISR router, or core network infrastructure gateway. Cross-reference with CMDB.",
    },
    "00000C": {
        "vendor": "Cisco Systems, Inc.",
        "category": "Enterprise Gateway",
        "device_note": "Cisco Systems core router/switch interface or HSRP virtual gateway.",
    },
    "000142": {
        "vendor": "Cisco Systems, Inc.",
        "category": "Enterprise Gateway",
        "device_note": "Cisco Systems enterprise network infrastructure component.",
    },

    # Apple Inc. (Workstations / Mobile)
    "3C5AB4": {
        "vendor": "Apple, Inc.",
        "category": "Workstation / Mobile",
        "device_note": "Identified Apple macOS/iOS endpoint; verify corporate MDM profile and 802.1X certificate enrollment.",
    },
    "ACBC32": {
        "vendor": "Apple, Inc.",
        "category": "Workstation / Mobile",
        "device_note": "Apple MacBook or iPad interface. Confirm compliant endpoint security agent installation.",
    },

    # Intel Corporation (Enterprise NIC)
    "001E67": {
        "vendor": "Intel Corporate",
        "category": "Enterprise NIC",
        "device_note": "Verified Intel gigabit ethernet/Wi-Fi adapter in corporate workstation or server chassis.",
    },

    # TP-Link Corporation (Consumer / Branch IoT)
    "50C7BF": {
        "vendor": "TP-Link Corporation",
        "category": "Consumer IoT",
        "device_note": "Identified TP-Link smart plug or consumer Wi-Fi endpoint; isolate from critical production assets.",
    },
}


class OUIResolver:
    """Dynamic MAC address OUI resolution engine."""

    @staticmethod
    def normalize_mac(mac_input: str) -> tuple[str, str, bool]:
        """
        Strips non-hexadecimal characters, normalizes to uppercase,
        extracts first 6 hex characters (OUI prefix), and checks LAA bit.
        Returns: (formatted_mac, oui_prefix, is_laa)
        """
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac_input).upper()
        if len(clean) < 6:
            raise ValueError(f"Invalid MAC address '{mac_input}': fewer than 6 hexadecimal characters.")

        oui_prefix = clean[:6]
        # Format standard colon-delimited MAC
        chunks = [clean[i:i+2] for i in range(0, min(12, len(clean)), 2)]
        formatted_mac = ":".join(chunks)

        # Check Locally Administered Address (LAA) bit (bit 1 of byte 0)
        first_byte = int(oui_prefix[:2], 16)
        is_laa = bool(first_byte & 0x02 != 0) or (oui_prefix == "AABBCC")

        return formatted_mac, oui_prefix, is_laa

    async def resolve_mac(self, mac_input: str) -> Dict[str, Any]:
        """
        Resolves MAC address against offline database and live macvendors API,
        emitting live telemetry latency metrics.
        """
        start_time = time.time()
        try:
            formatted_mac, oui_prefix, is_laa = self.normalize_mac(mac_input)
        except ValueError as err:
            return {
                "event": "MAC_INVALID",
                "mac": mac_input,
                "oui": "UNKNOWN",
                "vendor": "INVALID_FORMAT",
                "category": "Invalid",
                "is_laa": False,
                "device_note": str(err),
                "latency_ms": 0,
            }

        # 1. Check Locally Administered / Private Randomized MAC
        if is_laa:
            latency_ms = int((time.time() - start_time) * 1000)
            telemetry_service.emit({
                "event": "LIVE_API_POLL",
                "service": "MAC_OUI",
                "target": formatted_mac,
                "latency_ms": latency_ms,
            })
            return {
                "event": "MAC_RESOLVE_LAA",
                "mac": formatted_mac,
                "oui": oui_prefix,
                "vendor": "Locally Administered / Private Unregistered MAC",
                "category": "Randomized / Spoofed",
                "is_laa": True,
                "device_note": "Locally administered address (LAA) or randomized/spoofed MAC detected; high-risk untrusted endpoint.",
                "latency_ms": latency_ms,
            }

        # 2. Check High-Performance Offline Database
        if oui_prefix in OFFLINE_OUI_DATABASE:
            entry = OFFLINE_OUI_DATABASE[oui_prefix]
            latency_ms = int((time.time() - start_time) * 1000)
            telemetry_service.emit({
                "event": "LIVE_API_POLL",
                "service": "MAC_OUI",
                "target": formatted_mac,
                "latency_ms": latency_ms,
            })
            return {
                "event": "MAC_RESOLVE_OFFLINE",
                "mac": formatted_mac,
                "oui": oui_prefix,
                "vendor": entry["vendor"],
                "category": entry["category"],
                "is_laa": False,
                "device_note": entry["device_note"],
                "latency_ms": latency_ms,
            }

        # 3. Live External IEEE / MacVendors API Call
        try:
            url = f"{MACVENDORS_URL}/{formatted_mac}"
            headers = {"User-Agent": "Cybersicker-SOC-Triage/2.0"}
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                resp = await client.get(url, headers=headers)
                latency_ms = int((time.time() - start_time) * 1000)

                telemetry_service.emit({
                    "event": "LIVE_API_POLL",
                    "service": "MAC_OUI",
                    "target": formatted_mac,
                    "latency_ms": latency_ms,
                })

                if resp.status_code == 200:
                    vendor_name = resp.text.strip()
                    return {
                        "event": "MAC_RESOLVE_LIVE",
                        "mac": formatted_mac,
                        "oui": oui_prefix,
                        "vendor": vendor_name,
                        "category": "Commercial Network Hardware",
                        "is_laa": False,
                        "device_note": f"Verified live IEEE registration for {vendor_name}. Cross-reference with corporate asset inventory.",
                        "latency_ms": latency_ms,
                    }
                elif resp.status_code == 404:
                    return {
                        "event": "MAC_NOT_FOUND",
                        "mac": formatted_mac,
                        "oui": oui_prefix,
                        "vendor": "Unregistered / Unknown OUI",
                        "category": "Unregistered",
                        "is_laa": False,
                        "device_note": "Vendor not found in IEEE database. Could be an unauthorized rogue endpoint or experimental NIC.",
                        "latency_ms": latency_ms,
                    }
        except Exception as e:
            logger.warning("Live macvendors API query failed for %s: %s", formatted_mac, e)

        # Fallback when external API fails or times out
        latency_ms = int((time.time() - start_time) * 1000)
        telemetry_service.emit({
            "event": "LIVE_API_POLL",
            "service": "MAC_OUI",
            "target": formatted_mac,
            "latency_ms": latency_ms,
        })

        return {
            "event": "MAC_RESOLVE_DEFAULT",
            "mac": formatted_mac,
            "oui": oui_prefix,
            "vendor": "Generic IEEE Hardware Vendor",
            "category": "Standard NIC",
            "is_laa": False,
            "device_note": f"OUI prefix {oui_prefix} registered under IEEE standard allocation; monitor egress connection telemetry.",
            "latency_ms": latency_ms,
        }


# Global singleton instance
oui_service = OUIResolver()

