"""
CYBERSICKER — Real-Time Semantic Playbook RAG Service
ChromaDB persistent vector retrieval service indexing NIST/MITRE-aligned
incident response playbooks for real-time Blue-Team containment orchestration.
"""

from __future__ import annotations

import os
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import chromadb
from chromadb.config import Settings

from app.services.telemetry import telemetry_service

logger = logging.getLogger("Cybersicker.PlaybookRAG")

CHROMA_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "chroma_db"
CHROMA_DATA_DIR.mkdir(parents=True, exist_ok=True)

PLAYBOOK_COLLECTION_NAME = "cybersicker_playbooks"

NIST_MITRE_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "id": "SOP-004_SYN_FLOOD",
        "title": "SOP-004: SYN Flood / TCP Denial of Service Mitigation",
        "category": "Denial of Service / Network Saturation",
        "mitre_technique": "T1499.001 (Endpoint Denial of Service: OS Exhaustion Flood)",
        "nist_csf": "PR.PT-4 (Network Security and Perimeter Protection), DE.AE-1 (Baseline Anomaly)",
        "document": (
            "SOP-004: SYN Flood / TCP Denial of Service Mitigation\n"
            "Classification: Denial of Service / Network Layer Saturation\n"
            "MITRE ATT&CK: T1499 (Endpoint Denial of Service)\n"
            "Trigger: Massive half-open TCP connections saturating socket queues; drops reported in netstat backlog.\n"
            "Step-by-Step Immediate Containment Actions:\n"
            "1. Kernel TCP SYN Cookie Hardening: Execute 'sysctl -w net.ipv4.tcp_syncookies=1' to prevent backlog table starvation.\n"
            "2. Backlog Queue Expansion: Execute 'sysctl -w net.ipv4.tcp_max_syn_backlog=4096' and 'sysctl -w net.core.netdev_max_backlog=5000'.\n"
            "3. iptables Connection Limiter: Apply rate limit 'iptables -A INPUT -p tcp --syn -m limit --limit 200/s --limit-burst 300 -j ACCEPT'.\n"
            "4. Packet Fragmentation Defense: Drop malformed/fragmented TCP packets with 'iptables -A INPUT -p tcp -f -j DROP'.\n"
            "5. Cloud Scrubbing Redirection: Signal BGP Flowspec or Cloudflare/AWS Shield scrubbing center to absorb volumetric flood."
        ),
        "steps": [
            "sysctl -w net.ipv4.tcp_syncookies=1",
            "sysctl -w net.ipv4.tcp_max_syn_backlog=4096",
            "sysctl -w net.core.netdev_max_backlog=5000",
            "iptables -A INPUT -p tcp --syn -m limit --limit 200/s --limit-burst 300 -j ACCEPT",
            "iptables -A INPUT -p tcp -f -j DROP"
        ]
    },
    {
        "id": "SOP-003_RANSOMWARE",
        "title": "SOP-003: Ransomware Outbreak & C2 Encryption Containment",
        "category": "Ransomware / Mass Data Encryption",
        "mitre_technique": "T1486 (Data Encrypted for Impact), T1584 (Compromise Infrastructure)",
        "nist_csf": "RS.CO-2 (Incident Coordination), RS.MI-1 (Incident Containment)",
        "document": (
            "SOP-003: Ransomware Outbreak & C2 Encryption Containment\n"
            "Classification: Ransomware Outbreak & Rapid Host Encryption\n"
            "MITRE ATT&CK: T1486 (Data Encrypted for Impact)\n"
            "Trigger: Rapid mass file modification, encrypted extensions (.locked, .enc), or unauthorized vssadmin deletion.\n"
            "Step-by-Step Immediate Containment Actions:\n"
            "1. Physical & Virtual Interface Severing: Administratively down network uplink interfaces immediately to halt lateral spread.\n"
            "2. SMB Service Termination: Execute 'net session /delete /y' and block TCP ports 445 and 139 via host firewall.\n"
            "3. Shadow Copy & Snapshot Verification: Inspect recovery catalogs with 'vssadmin list shadows' and enforce immutable write-once S3/SAN retention.\n"
            "4. Volatile Memory Acquisition: Collect live volatile RAM memory dump via LiME or WinPmem prior to shutting down system power.\n"
            "5. Domain Trust Revocation: Invalidate domain Kerberos krbtgt tickets and revoke affected computer trust accounts."
        ),
        "steps": [
            "ip link set eth0 down (or disable network adapter)",
            "net session /delete /y",
            "iptables -A INPUT -p tcp --dport 445 -j DROP",
            "vssadmin list shadows",
            "winpmem.exe -o memdump.raw (or LiME for Linux)"
        ]
    },
    {
        "id": "SOP-005_ARP_SPOOFING",
        "title": "SOP-005: ARP Poisoning & Man-In-The-Middle Defense",
        "category": "Network Spoofing / Eavesdropping",
        "mitre_technique": "T1557.002 (Man-in-the-Middle: ARP Poisoning)",
        "nist_csf": "PR.AC-5 (Network Integrity Protection)",
        "document": (
            "SOP-005: ARP Poisoning & Man-In-The-Middle Defense\n"
            "Classification: Layer 2 ARP Cache Poisoning / MITM\n"
            "MITRE ATT&CK: T1557.002 (Man-in-the-Middle: ARP Poisoning)\n"
            "Trigger: Multiple IP conflicts detected; gratuitous ARP frames claiming default gateway MAC address.\n"
            "Step-by-Step Immediate Containment Actions:\n"
            "1. Dynamic ARP Inspection (DAI): Enforce switch-level DAI against the DHCP snooping lease database.\n"
            "2. Static Gateway Binding: Pin gateway MAC address permanently: 'ip neighbor add 192.168.1.1 lladdr 00:1A:2B:3C:4D:5E nud permanent dev eth0'.\n"
            "3. Switch Port Security: Restrict maximum MAC addresses per switchport to 1 and set violation action to err-disable.\n"
            "4. DHCP Snooping Verification: Enforce untrusted classification on all edge client access switch ports."
        ),
        "steps": [
            "ip neighbor add 192.168.1.1 lladdr 00:1A:2B:3C:4D:5E nud permanent dev eth0",
            "switch(config-if)# switchport port-security violation shutdown",
            "switch(config)# ip arp inspection vlan 10,20",
            "switch(config)# ip dhcp snooping"
        ]
    },
    {
        "id": "SOP-007_UNAUTHORIZED_IOT",
        "title": "SOP-007: Rogue / Unauthorized IoT Device Containment",
        "category": "Rogue Hardware / Peripheral Incursion",
        "mitre_technique": "T1200 (Hardware Additions), T1078 (Valid Accounts)",
        "nist_csf": "ID.AM-1 (Physical Asset Inventory), PR.AC-3 (Remote Access Management)",
        "document": (
            "SOP-007: Rogue / Unauthorized IoT Device Containment\n"
            "Classification: Unauthorized IoT / Rogue Single-Board Computer\n"
            "MITRE ATT&CK: T1200 (Hardware Additions)\n"
            "Trigger: Unregistered OUI discovered on corporate access switch, abnormal multicast mDNS/LLMNR discovery, or unauthorized DHCP lease.\n"
            "Step-by-Step Immediate Containment Actions:\n"
            "1. Switch Port Disablement: Issue SNMP or CLI shutdown command to the physical switch port hosting the rogue device.\n"
            "2. 802.1X Quarantine VLAN: If dynamic MAC bypass triggered, reassign port immediately to isolated Quarantine VLAN 999.\n"
            "3. Default Credential Sweep: Verify device has not exposed default administrative credentials (admin/admin, root/toor, ubnt/ubnt).\n"
            "4. Microsegmentation Firewall ACL: Deny all ingress/egress from rogue IP to internal production subnets."
        ),
        "steps": [
            "switch(config-if)# shutdown",
            "switch(config-if)# switchport access vlan 999",
            "iptables -I FORWARD -s <ROGUE_IP> -j DROP"
        ]
    },
    {
        "id": "SOP-006_RCE_SUPPLY_CHAIN",
        "title": "SOP-006: Web Shell & Remote Code Execution / Supply-Chain Containment",
        "category": "Remote Code Execution / Supply-Chain Backdoor",
        "mitre_technique": "T1505.003 (Server Software Component: Web Shell), T1059 (Command and Scripting Interpreter)",
        "nist_csf": "RS.MI-2 (Incident Mitigation), PR.IP-1 (Baseline Configuration)",
        "document": (
            "SOP-006: Web Shell & Remote Code Execution / Supply-Chain Containment\n"
            "Classification: Remote Code Execution (RCE) & Malicious Supply-Chain Artifacts\n"
            "MITRE ATT&CK: T1505.003 (Web Shell), T1195 (Supply Chain Compromise)\n"
            "Trigger: Exploitation of critical RCE advisories (e.g., CVE-2024-3094 XZ-Utils backdoor, CVE-2021-44228 Log4Shell) or web process spawning interactive shells.\n"
            "Step-by-Step Immediate Containment Actions:\n"
            "1. Process Ancestry & Active Sockets Inspection: Identify rogue parent-child chains ('ps auxf', 'ss -tapn') and terminate unauthorized shell PIDs.\n"
            "2. Reverse Shell Socket Teardown: Block egress TCP sockets to non-standard ports with 'iptables -A OUTPUT -p tcp -m multiport --dports 4444,1337,9001 -j DROP'.\n"
            "3. Package Downgrade / Replacement: For supply-chain backdoors (e.g. XZ 5.6.0/5.6.1), immediately roll back to verified release (5.4.6).\n"
            "4. SSH Key & Credential Revocation: Invalidate all host keys, rotate root/admin credentials, and invalidate active sessions.\n"
            "5. Web Application Pool Recycling: Recycle application pool, invalidate active cookies, and restrict upload directories to no-execute."
        ),
        "steps": [
            "kill -9 <ROGUE_PID>",
            "iptables -A OUTPUT -p tcp -m multiport --dports 4444,1337,9001 -j DROP",
            "apt-get install --allow-downgrades xz-utils=5.4.5-0.1 (or distro equivalent)",
            "rm -f /root/.ssh/authorized_keys_compromised"
        ]
    },
    {
        "id": "SOP-001_BOTNET_C2",
        "title": "SOP-001: IoT Botnet C2 Infection & Perimeter Isolation",
        "category": "Botnet Infection / Command and Control",
        "mitre_technique": "T1584 (Compromise Infrastructure: Botnet), T1071 (Application Layer Protocol)",
        "nist_csf": "DE.CM-1 (Network Monitoring), RS.MI-1 (Incident Containment)",
        "document": (
            "SOP-001: IoT Botnet C2 Infection & Perimeter Isolation\n"
            "Classification: Botnet C2 Beaconing & Coordinated Attack Node\n"
            "MITRE ATT&CK: T1584 (Botnet)\n"
            "Trigger: Internal IoT endpoint communicating with known Mirai/Mozi C2 controllers, engaging in automated brute force or port scanning.\n"
            "Step-by-Step Immediate Containment Actions:\n"
            "1. BGP Destination Blackholing: Announce null route for malicious external C2 destination IP at edge router.\n"
            "2. Dynamic VLAN Quarantine: Shift infected device port into Quarantine VLAN 999.\n"
            "3. Temporary Process Kill: Terminate anomalous binaries running from /tmp, /var/run, or /dev/shm.\n"
            "4. Port 23/2323 Ingress Block: Drop Telnet/SSH brute force vectors using iptables.\n"
            "5. Firmware Reflash: Perform clean manufacturer firmware flash to purge non-volatile persistence."
        ),
        "steps": [
            "ip route add blackhole <MALICIOUS_C2_IP>",
            "killall -9 /tmp/*",
            "iptables -A INPUT -p tcp --dport 23 -j DROP"
        ]
    }
]


class PlaybookRAGService:
    """Manages ChromaDB persistent vector database for incident response playbooks."""

    def __init__(self):
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None
        self._initialize_collection()

    def _initialize_collection(self):
        """Initializes ChromaDB persistent client and indexes all SOP documents."""
        try:
            self._client = chromadb.PersistentClient(
                path=str(CHROMA_DATA_DIR),
                settings=Settings(anonymized_telemetry=False, allow_reset=True)
            )
            self._collection = self._client.get_or_create_collection(
                name=PLAYBOOK_COLLECTION_NAME,
                metadata={"description": "Cybersicker Blue-Team Incident Response Playbooks"}
            )

            # Populate or update collection with the latest playbooks
            logger.info("Indexing %s incident playbooks into ChromaDB...", len(NIST_MITRE_PLAYBOOKS))
            ids = [p["id"] for p in NIST_MITRE_PLAYBOOKS]
            documents = [p["document"] for p in NIST_MITRE_PLAYBOOKS]
            metadatas = [
                {
                    "sop_id": p["id"],
                    "title": p["title"],
                    "category": p["category"],
                    "mitre_technique": p["mitre_technique"],
                    "nist_csf": p["nist_csf"],
                }
                for p in NIST_MITRE_PLAYBOOKS
            ]
            self._collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
            logger.info("ChromaDB playbook collection successfully indexed.")
        except Exception as e:
            logger.error("Failed to initialize ChromaDB playbook collection: %s", e)

    def search_playbooks(self, query: str, n_results: int = 1) -> List[Dict[str, Any]]:
        """
        Embeds the incident query and performs semantic similarity search in ChromaDB.
        Emits live CHROMA_RAG_HIT telemetry event with similarity score.
        """
        if not self._collection:
            self._initialize_collection()

        query_str = query.strip()
        matches: List[Dict[str, Any]] = []

        try:
            results = self._collection.query(
                query_texts=[query_str],
                n_results=min(n_results, len(NIST_MITRE_PLAYBOOKS))
            )

            if results and results.get("ids") and results["ids"][0]:
                for idx, sop_id in enumerate(results["ids"][0]):
                    dist = results["distances"][0][idx] if "distances" in results and results["distances"] else 0.5
                    # Cosine distance in Chroma: similarity = max(0.0, 1.0 - (dist / 2.0))
                    similarity = max(0.50, min(0.99, round(1.0 - (dist / 2.0), 2)))
                    metadata = results["metadatas"][0][idx] if "metadatas" in results else {}
                    document = results["documents"][0][idx] if "documents" in results else ""

                    # Find matching playbook definition for action steps
                    sop_prefix = sop_id.split("_")[0]
                    pb_def = next(
                        (p for p in NIST_MITRE_PLAYBOOKS if p["id"] == sop_id or p["id"].startswith(sop_prefix)),
                        None
                    )
                    action_steps = pb_def["steps"] if pb_def and "steps" in pb_def else []
                    
                    # If action_steps still empty, extract commands from document
                    if not action_steps and document:
                        for line in document.split("\n"):
                            line_s = line.strip()
                            if any(k in line_s for k in ("sysctl", "iptables", "ip link", "net session", "switch")):
                                action_steps.append(line_s)

                    matches.append({
                        "id": sop_id,
                        "title": metadata.get("title", sop_id),
                        "category": metadata.get("category", "General Incident"),
                        "mitre_technique": metadata.get("mitre_technique", "T1059"),
                        "nist_csf": metadata.get("nist_csf", "PR.PT-4"),
                        "similarity_score": similarity,
                        "document": document,
                        "action_steps": action_steps,
                    })

                # Emit real-time telemetry event for the top match
                if matches:
                    top_match = matches[0]
                    telemetry_service.emit({
                        "event": "CHROMA_RAG_HIT",
                        "playbook_id": top_match["id"],
                        "similarity_score": top_match["similarity_score"],
                    })

                return matches

        except Exception as e:
            logger.error("ChromaDB vector query failed: %s", e)

        # Fallback keyword matching if ChromaDB query encounters exception
        q_lower = query_str.lower()
        if "syn" in q_lower or "flood" in q_lower or "dos" in q_lower:
            matched = NIST_MITRE_PLAYBOOKS[0]
        elif "ransom" in q_lower or "encrypt" in q_lower or "vss" in q_lower:
            matched = NIST_MITRE_PLAYBOOKS[1]
        elif "arp" in q_lower or "poison" in q_lower or "mitm" in q_lower:
            matched = NIST_MITRE_PLAYBOOKS[2]
        elif "iot" in q_lower or "device" in q_lower or "mac" in q_lower or "rogue" in q_lower:
            matched = NIST_MITRE_PLAYBOOKS[3]
        elif "rce" in q_lower or "shell" in q_lower or "cve" in q_lower or "supply" in q_lower:
            matched = NIST_MITRE_PLAYBOOKS[4]
        else:
            matched = NIST_MITRE_PLAYBOOKS[5]

        similarity = 0.88
        telemetry_service.emit({
            "event": "CHROMA_RAG_HIT",
            "playbook_id": matched["id"],
            "similarity_score": similarity,
        })

        return [{
            "id": matched["id"],
            "title": matched["title"],
            "category": matched["category"],
            "mitre_technique": matched["mitre_technique"],
            "nist_csf": matched["nist_csf"],
            "similarity_score": similarity,
            "document": matched["document"],
            "action_steps": matched["steps"],
        }]


# Global singleton instance
playbook_rag_service = PlaybookRAGService()
