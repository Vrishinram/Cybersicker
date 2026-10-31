"""
CYBERSICKER — ChromaDB Contextual Playbook Retrieval (RAG) Service
Performs semantic vector matching against granular SOC defense runbooks.
"""

import os
from typing import Dict, Any, List, Optional
from pathlib import Path
import chromadb
from chromadb.config import Settings

# Persistent Chroma storage directory
CHROMA_PERSIST_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "chroma_db"
CHROMA_PERSIST_DIR.mkdir(parents=True, exist_ok=True)

# Granular defense runbooks
GRANULAR_SOP_CORPUS = [
    {
        "id": "SOP-001",
        "title": "IoT Botnet Infection Response",
        "document": (
            "SOP-001: IoT Botnet Infection Response\n"
            "Trigger: Device exhibits C2 beaconing behavior, participates in coordinated scanning, or sends outbound traffic to known botnet infrastructure (Mirai, Mozi, BotenaGo, Enemybot).\n"
            "Containment Phase:\n"
            "1. Dynamic VLAN Quarantine: Reassign switch port or Wi-Fi BSSID to Quarantine VLAN 999.\n"
            "2. External C2 Teardown: Blackhole malicious IP destination at upstream border BGP/firewall.\n"
            "3. Process Termination: Terminate suspicious child processes spawned from /tmp or /var/run.\n"
            "4. Credential Revocation: Invalidate default Telnet/SSH credentials and rotate API tokens."
        ),
        "metadata": {"sop_id": "SOP-001", "severity": "CRITICAL", "framework": "MITRE ATT&CK T1584"}
    },
    {
        "id": "SOP-002",
        "title": "ICMP Flood / DDoS Mitigation",
        "document": (
            "SOP-002: ICMP Flood & Volumetric DDoS Mitigation\n"
            "Trigger: Abnormal ingress/egress ICMP packet rates exceeding 5,000 pps, triggering link saturation or gateway CPU exhaustion.\n"
            "Containment Phase:\n"
            "1. Edge Filtering: Apply iptables rate-limiting: iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 50/s --limit-burst 100 -j ACCEPT\n"
            "2. Drop Threshold: iptables -A INPUT -p icmp -j DROP\n"
            "3. BGP Flowspec / Cloud Scrubbing: Signal upstream ISP transit to redirect volumetric prefixes to scrubbing center.\n"
            "4. Source Attribution: Inspect netflow telemetry for reflection/amplification source addresses."
        ),
        "metadata": {"sop_id": "SOP-002", "severity": "HIGH", "framework": "NIST CSF PR.PT-4"}
    },
    {
        "id": "SOP-003",
        "title": "IoT Ransomware Outbreak Containment",
        "document": (
            "SOP-003: IoT Ransomware Outbreak Containment\n"
            "Trigger: Massive anomalous file rename events (.encrypted, .locked), unauthorized mass writes, or rapid SMB/NFS encryption activity.\n"
            "Containment Phase:\n"
            "1. Physical & Virtual Isolation: Sever uplink interface immediately; disable SMBv1/v2 ports (TCP 445, 139).\n"
            "2. Shadow Copy & Snapshot Verification: Audit volume shadow copies via vssadmin and lock immutable storage snapshots.\n"
            "3. Key Revocation: Isolate domain controller trusts if active directory joined; revoke compromised Kerberos tickets.\n"
            "4. Forensic Preservation: Take live RAM image using LiME or FTK Imager prior to power down."
        ),
        "metadata": {"sop_id": "SOP-003", "severity": "CRITICAL", "framework": "MITRE ATT&CK T1486"}
    },
    {
        "id": "SOP-004",
        "title": "DoS / TCP SYN Flood Mitigation",
        "document": (
            "SOP-004: DoS / TCP SYN Flood Mitigation\n"
            "Trigger: High volume of half-open TCP connections filling SYN backlog queue (netstat -s: 'SYNs to LISTEN sockets dropped').\n"
            "Containment Phase:\n"
            "1. Kernel SYN Cookies: sysctl -w net.ipv4.tcp_syncookies=1\n"
            "2. Backlog Tuning: sysctl -w net.ipv4.tcp_max_syn_backlog=4096 && sysctl -w net.core.netdev_max_backlog=5000\n"
            "3. iptables Rate Limiting: iptables -A INPUT -p tcp --syn -m limit --limit 200/s --limit-burst 300 -j ACCEPT\n"
            "4. Ingress Filtering: Drop fragmented TCP packets: iptables -A INPUT -p tcp -f -j DROP\n"
            "5. SYN Proxy Deployment: Enable hardware SYN-Proxy on perimeter appliance to validate 3-way handshakes."
        ),
        "metadata": {"sop_id": "SOP-004", "severity": "HIGH", "framework": "NIST CSF DE.AE-1"}
    },
    {
        "id": "SOP-005",
        "title": "ARP Spoofing & Cache Poisoning Defense",
        "document": (
            "SOP-005: ARP Spoofing & Cache Poisoning Defense\n"
            "Trigger: Duplicate IP notifications in syslog or gratuitous ARP flood mapping gateway IP to attacker MAC address.\n"
            "Containment Phase:\n"
            "1. Dynamic ARP Inspection (DAI): Enable DAI on managed switches against DHCP snooping binding database.\n"
            "2. Static Gateway Binding: Pin default gateway MAC: ip neighbor add 192.168.1.1 lladdr 00:1A:2B:3C:4D:5E nud permanent dev eth0\n"
            "3. Arpwatch Alerting: Trigger real-time alert on Ethernet MAC/IP address pairing changes.\n"
            "4. Port Security: Restrict maximum MAC addresses per switch port to 1; enable err-disable on violation."
        ),
        "metadata": {"sop_id": "SOP-005", "severity": "MEDIUM", "framework": "MITRE ATT&CK T1557.002"}
    },
    {
        "id": "SOP-006",
        "title": "Supply Chain & RCE Vulnerability Containment",
        "document": (
            "SOP-006: Supply Chain & Remote Code Execution Containment\n"
            "Trigger: Exploitation of critical RCE advisories (e.g., CVE-2021-44228 Log4Shell, CVE-2024-3094 XZ-Utils backdoor).\n"
            "Containment Phase:\n"
            "1. Parameter Disablement: For Log4j, set LOG4J_FORMAT_MSG_NO_LOOKUPS=true or upgrade to >= 2.17.1.\n"
            "2. Binary Downgrade: For XZ-Utils, downgrade liblzma to 5.4.6; terminate active sshd child sessions.\n"
            "3. Egress ACL Enforcement: Block egress LDAP (389, 636) and RMI (1099) ports toward external hosts.\n"
            "4. Host Key Rotation: Invalidate all SSH host and authorized keys across potentially compromised fleet endpoints."
        ),
        "metadata": {"sop_id": "SOP-006", "severity": "CRITICAL", "framework": "NIST CSF PR.IP-1"}
    }
]

class ChromaPlaybookRAG:
    """Manages ChromaDB vector database initialization, embedding, and semantic similarity search."""

    def __init__(self, persist_dir: Optional[str] = None):
        self.persist_dir = persist_dir or str(CHROMA_PERSIST_DIR)
        self.client = chromadb.PersistentClient(path=self.persist_dir)
        self.collection = self.client.get_or_create_collection(
            name="cybersicker_playbooks",
            metadata={"hnsw:space": "cosine"}
        )
        self._ensure_corpus_indexed()

    def _ensure_corpus_indexed(self):
        """Seeds granular runbooks into the vector store if not already present."""
        existing = self.collection.get()
        existing_ids = set(existing.get("ids", []))

        to_add_docs = []
        to_add_metas = []
        to_add_ids = []

        for item in GRANULAR_SOP_CORPUS:
            if item["id"] not in existing_ids:
                to_add_docs.append(item["document"])
                to_add_metas.append(item["metadata"])
                to_add_ids.append(item["id"])

        if to_add_ids:
            self.collection.add(
                documents=to_add_docs,
                metadatas=to_add_metas,
                ids=to_add_ids
            )

    def search_playbook(self, query: str, n_results: int = 2) -> Dict[str, Any]:
        """
        Embeds the query and retrieves the top-k semantically matched runbooks from ChromaDB.
        Returns match metadata, document text, and calculated similarity score.
        """
        if not query or not query.strip():
            query = "General incident response containment"

        results = self.collection.query(
            query_texts=[query],
            n_results=min(n_results, len(GRANULAR_SOP_CORPUS))
        )

        matched_docs = results.get("documents", [[]])[0]
        matched_metas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        if not matched_docs:
            return {
                "matched": False,
                "sop_id": "NONE",
                "title": "General IoT Containment",
                "similarity_score": 0.0,
                "content": "No specific runbook match found in ChromaDB collection.",
                "telemetry_event": None
            }

        top_doc = matched_docs[0]
        top_meta = matched_metas[0] if matched_metas else {}
        distance = distances[0] if distances else 0.5
        
        # In cosine distance: 0 = identical, 1 = orthogonal, 2 = opposite.
        # Normalize to similarity score between 0.0 and 1.0:
        similarity_score = max(0.0, min(1.0, 1.0 - (distance / 2.0)))
        sop_id = top_meta.get("sop_id", "SOP-UNKNOWN")

        telemetry_event = {
            "event": "CHROMA_RAG_MATCH",
            "sop_id": sop_id,
            "similarity_score": round(similarity_score, 2)
        }

        # Multi-doc compilation
        compiled_text = "\n\n---\n\n".join(matched_docs)

        return {
            "matched": True,
            "sop_id": sop_id,
            "title": top_doc.split("\n")[0] if "\n" in top_doc else sop_id,
            "similarity_score": round(similarity_score, 2),
            "content": compiled_text,
            "telemetry_event": telemetry_event
        }


# Global singleton instance
playbook_rag = ChromaPlaybookRAG()
