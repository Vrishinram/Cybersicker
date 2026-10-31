"""
CYBERSICKER — Real-Time PCAP Flow Reconstructor & Feature Extraction
Parses raw packet captures (.pcap, .pcapng) using Scapy, reconstructs bidirectional
TCP/UDP network flows, and computes the 41 standard statistical traffic features
(NSL-KDD baseline) for deep autoencoder anomaly detection.
"""

from __future__ import annotations

import os
import time
import tempfile
import logging
from typing import Dict, Any, List, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

logger = logging.getLogger("Cybersicker.PCAPExtractor")

# Standard Service Port Mapping
PORT_SERVICE_MAP = {
    80: "http", 443: "http", 8080: "http", 8443: "http",
    53: "dns", 22: "ssh", 23: "telnet", 25: "smtp",
    21: "ftp", 20: "ftp_data", 110: "pop_3", 143: "imap4",
    123: "ntp", 161: "snmp", 162: "snmp", 389: "ldap",
    636: "ldap", 445: "smb", 139: "netbios_ssn", 137: "netbios_ns",
    3389: "rdp", 1883: "mqtt", 8883: "mqtt_tls", 5683: "coap"
}

# The 38 Numerical Feature Names in NSL-KDD (Ordered)
KDD_NUMERICAL_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]


@dataclass
class PacketMeta:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    payload_len: int
    flags: str
    is_syn: bool = False
    is_synack: bool = False
    is_rst: bool = False
    is_fin: bool = False


@dataclass
class FlowRecord:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol_type: str
    service: str
    start_time: float
    end_time: float
    src_bytes: int = 0
    dst_bytes: int = 0
    packet_count: int = 0
    flags: List[str] = field(default_factory=list)
    has_syn: bool = False
    has_synack: bool = False
    has_rst: bool = False
    has_fin: bool = False
    urgent_count: int = 0


def parse_pcap_to_flows(pcap_bytes: bytes) -> List[FlowRecord]:
    """
    Parses raw PCAP bytes into bidirectional network flows.
    """
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP

    flows: Dict[Tuple[str, str, int, int, str], FlowRecord] = {}
    temp_path = None

    try:
        # Write bytes to temp file for reliable multi-platform Scapy parsing
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            tf.write(pcap_bytes)
            temp_path = tf.name

        packets = rdpcap(temp_path)
        logger.info("Successfully read %d packets from PCAP", len(packets))

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_time = float(pkt.time)
            payload_len = len(ip_layer.payload)

            src_port = 0
            dst_port = 0
            proto = "other"
            flags_str = ""
            is_syn = False
            is_synack = False
            is_rst = False
            is_fin = False
            urgent = 0

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                proto = "tcp"
                flags_str = str(tcp.flags)
                is_syn = "S" in flags_str and "A" not in flags_str
                is_synack = "S" in flags_str and "A" in flags_str
                is_rst = "R" in flags_str
                is_fin = "F" in flags_str
                urgent = 1 if "U" in flags_str else 0
                payload_len = len(tcp.payload)

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)
                proto = "udp"
                payload_len = len(udp.payload)

            elif pkt.haslayer(ICMP):
                proto = "icmp"
                src_port = 0
                dst_port = 0

            # Forward and reverse flow keys
            fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
            rev_key = (dst_ip, src_ip, dst_port, src_port, proto)

            if fwd_key in flows:
                flow = flows[fwd_key]
                flow.end_time = max(flow.end_time, pkt_time)
                flow.src_bytes += payload_len
                flow.packet_count += 1
                if is_rst: flow.has_rst = True
                if is_fin: flow.has_fin = True
            elif rev_key in flows:
                flow = flows[rev_key]
                flow.end_time = max(flow.end_time, pkt_time)
                flow.dst_bytes += payload_len
                flow.packet_count += 1
                if is_synack: flow.has_synack = True
                if is_rst: flow.has_rst = True
                if is_fin: flow.has_fin = True
            else:
                # Determine service from destination port or source port
                srv = PORT_SERVICE_MAP.get(dst_port) or PORT_SERVICE_MAP.get(src_port) or "private"
                flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto}"
                flows[fwd_key] = FlowRecord(
                    flow_id=flow_id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol_type=proto,
                    service=srv,
                    start_time=pkt_time,
                    end_time=pkt_time,
                    src_bytes=payload_len,
                    dst_bytes=0,
                    packet_count=1,
                    has_syn=is_syn,
                    has_synack=is_synack,
                    has_rst=is_rst,
                    has_fin=is_fin,
                    urgent_count=urgent
                )

    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

    return list(flows.values())


def extract_kdd_features_from_flows(flows: List[FlowRecord]) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    """
    Transforms FlowRecord objects into a 38-feature numerical DataFrame matching
    NSL-KDD baseline requirements for the Autoencoder, plus flow endpoint metadata.
    """
    if not flows:
        return pd.DataFrame(), []

    # Sort flows by start_time to calculate sliding window statistics
    flows_sorted = sorted(flows, key=lambda f: f.start_time)
    num_flows = len(flows_sorted)

    rows = []
    endpoint_metadata = []

    for i, flow in enumerate(flows_sorted):
        duration = max(0.0, flow.end_time - flow.start_time)
        land = 1 if (flow.src_ip == flow.dst_ip and flow.src_port == flow.dst_port and flow.src_port > 0) else 0

        # Connection status flag representation
        if flow.has_rst:
            flag = "REJ"
        elif flow.has_syn and not flow.has_synack:
            flag = "S0"
        elif flow.has_syn and flow.has_synack:
            flag = "SF"
        else:
            flag = "SF"

        # Compute 2-second time window statistics across preceding flows
        t_cur = flow.start_time
        window_flows = [
            f for f in flows_sorted[max(0, i - 150):i + 1]
            if 0 <= (t_cur - f.start_time) <= 2.0
        ]

        # Host-level and service-level counts in window
        same_dst_host = [f for f in window_flows if f.dst_ip == flow.dst_ip]
        same_srv = [f for f in window_flows if f.service == flow.service]

        count = len(same_dst_host)
        srv_count = len(same_srv)

        # SYN error rates in window
        syn_err_count = sum(1 for f in same_dst_host if f.has_syn and not f.has_synack)
        serror_rate = round(syn_err_count / max(1, count), 4)

        srv_syn_err_count = sum(1 for f in same_srv if f.has_syn and not f.has_synack)
        srv_serror_rate = round(srv_syn_err_count / max(1, srv_count), 4)

        same_srv_count = sum(1 for f in same_dst_host if f.service == flow.service)
        same_srv_rate = round(same_srv_count / max(1, count), 4)
        diff_srv_rate = round((count - same_srv_count) / max(1, count), 4)

        # Destination host statistics (across past 100 connections)
        hist_dst = [f for f in flows_sorted[max(0, i - 100):i + 1] if f.dst_ip == flow.dst_ip]
        dst_host_count = min(255, len(hist_dst))
        hist_dst_srv = [f for f in hist_dst if f.service == flow.service]
        dst_host_srv_count = min(255, len(hist_dst_srv))

        dst_host_same_srv_rate = round(len(hist_dst_srv) / max(1, len(hist_dst)), 4)
        dst_host_diff_srv_rate = round(1.0 - dst_host_same_srv_rate, 4)

        # Build numerical feature row (38 numerical values)
        row = {
            "duration": float(duration),
            "src_bytes": float(flow.src_bytes),
            "dst_bytes": float(flow.dst_bytes),
            "land": float(land),
            "wrong_fragment": 0.0,
            "urgent": float(flow.urgent_count),
            "hot": 0.0,
            "num_failed_logins": 0.0,
            "logged_in": 1.0 if flow.dst_bytes > 0 else 0.0,
            "num_compromised": 0.0,
            "root_shell": 0.0,
            "su_attempted": 0.0,
            "num_root": 0.0,
            "num_file_creations": 0.0,
            "num_shells": 0.0,
            "num_access_files": 0.0,
            "num_outbound_cmds": 0.0,
            "is_host_login": 0.0,
            "is_guest_login": 0.0,
            "count": float(count),
            "srv_count": float(srv_count),
            "serror_rate": float(serror_rate),
            "srv_serror_rate": float(srv_serror_rate),
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": float(same_srv_rate),
            "diff_srv_rate": float(diff_srv_rate),
            "srv_diff_host_rate": 0.0,
            "dst_host_count": float(dst_host_count),
            "dst_host_srv_count": float(dst_host_srv_count),
            "dst_host_same_srv_rate": float(dst_host_same_srv_rate),
            "dst_host_diff_srv_rate": float(dst_host_diff_srv_rate),
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": float(serror_rate),
            "dst_host_srv_serror_rate": float(srv_serror_rate),
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0,
        }
        rows.append(row)

        endpoint_metadata.append({
            "flow_id": flow.flow_id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol_type,
            "service": flow.service,
            "packets": flow.packet_count,
            "duration": round(duration, 3),
            "bytes_total": flow.src_bytes + flow.dst_bytes
        })

    df = pd.DataFrame(rows)
    return df, endpoint_metadata
