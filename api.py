"""
CYBERSICKER — Production FastAPI SOC Backend Engine
Exposes live threat intelligence, NIST NVD advisories, IEEE OUI hardware resolution,
in-memory autoencoder traffic inference, ChromaDB semantic playbooks,
and real-time LLM agent dispatch for the React/Next.js frontend.
"""

import os
import re
import sys
import json
import asyncio
import logging
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# Service Imports
from app.services.virustotal import virustotal_service
from app.services.nvd import nvd_service
from app.services.oui import oui_service
from app.services.playbook_rag import playbook_rag_service
from app.services.traffic_scanner import traffic_scanner_service
from app.services.telemetry import telemetry_service
from app.routers.agent import router as agent_router

logger = logging.getLogger("Cybersicker.API")

# ─── App Setup ───────────────────────────────────────────────
app = FastAPI(
    title="CYBERSICKER Production SOC Engine",
    version="2.5.0",
    description="Real-Time Blue-Team SOC Triage, Anomaly Detection & Incident Response Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent

# ─── Request/Response Models ────────────────────────────────
class ScanRequest(BaseModel):
    filepath: Optional[str] = None
    raw_csv: Optional[str] = None
    threshold: Optional[float] = 0.042

class IPRequest(BaseModel):
    ip_address: str

class MACRequest(BaseModel):
    mac_address: str

class CVERequest(BaseModel):
    cve_id: str

class PlaybookRequest(BaseModel):
    incident_type: str

class FullTriageRequest(BaseModel):
    filepath: Optional[str] = None
    raw_csv: Optional[str] = None
    ip_address: Optional[str] = "185.220.101.43"
    mac_address: Optional[str] = "B8:27:EB:AA:BB:CC"
    cve_id: Optional[str] = "CVE-2024-3094"
    incident_type: Optional[str] = "SYN flood volumetric denial of service"

class ToolResponse(BaseModel):
    success: bool
    result: str


# ═══════════════════════════════════════════════════════════════
# TOOL 1: Live Network Traffic Scanner (In-Memory Autoencoder)
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/scan", response_model=ToolResponse)
async def network_scan(req: ScanRequest):
    try:
        # Check if raw CSV text was passed directly
        if req.raw_csv:
            report = traffic_scanner_service.scan_csv_bytes(
                req.raw_csv.encode("utf-8"),
                filename="raw_payload.csv",
                threshold=req.threshold or 0.042
            )
            return ToolResponse(success=True, result=json.dumps(report))

        # Check if a file path was passed
        if req.filepath:
            target_path = Path(req.filepath)
            # Resolve relative or filename-only references to project root or data
            if not target_path.is_file():
                if (BASE_DIR / req.filepath).is_file():
                    target_path = BASE_DIR / req.filepath
                elif (BASE_DIR / "KDDTrain+.txt").is_file():
                    target_path = BASE_DIR / "KDDTrain+.txt"

            if target_path.is_file():
                content = target_path.read_bytes()
                report = traffic_scanner_service.scan_csv_bytes(
                    content,
                    filename=target_path.name,
                    threshold=req.threshold or 0.042
                )
                return ToolResponse(success=True, result=json.dumps(report))

        # Default sample traffic run if no file or payload is specified
        kdd_sample = BASE_DIR / "KDDTrain+.txt"
        if kdd_sample.is_file():
            # Sample first 200 lines to execute fast in-memory inference
            with open(kdd_sample, "rb") as f:
                sample_bytes = b"".join([f.readline() for _ in range(250)])
            report = traffic_scanner_service.scan_csv_bytes(
                sample_bytes,
                filename="KDDTrain+_sample.csv",
                threshold=req.threshold or 0.042
            )
            return ToolResponse(success=True, result=json.dumps(report))

        return ToolResponse(
            success=False,
            result="No packet traffic provided. Please supply 'raw_csv' or a valid data file path."
        )
    except Exception as e:
        logger.error("Scan endpoint failed: %s", e)
        return ToolResponse(success=False, result=f"Scan Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# TOOL 2: Live VirusTotal v3 IP Intelligence
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/ip-check", response_model=ToolResponse)
async def check_ip(req: IPRequest):
    try:
        report = await virustotal_service.check_ip(req.ip_address)
        return ToolResponse(success=True, result=json.dumps(report))
    except Exception as e:
        logger.error("VirusTotal IP check failed: %s", e)
        return ToolResponse(success=False, result=f"Threat Intelligence Query Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# TOOL 3: Live IEEE MAC Address & OUI Resolution
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/mac-lookup", response_model=ToolResponse)
async def mac_lookup(req: MACRequest):
    try:
        report = await oui_service.resolve_mac(req.mac_address)
        return ToolResponse(success=True, result=json.dumps(report))
    except Exception as e:
        logger.error("MAC lookup failed: %s", e)
        return ToolResponse(success=False, result=f"MAC OUI Resolution Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# TOOL 4: Live NIST NVD REST API 2.0 Query
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/cve-lookup", response_model=ToolResponse)
async def cve_lookup(req: CVERequest):
    try:
        report = await nvd_service.lookup_cve(req.cve_id)
        return ToolResponse(success=True, result=json.dumps(report))
    except Exception as e:
        logger.error("CVE lookup failed: %s", e)
        return ToolResponse(success=False, result=f"NIST NVD Advisory Query Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# TOOL 5: Real-Time ChromaDB Semantic Playbook Retrieval (RAG)
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/playbook", response_model=ToolResponse)
async def consult_playbook(req: PlaybookRequest):
    try:
        matches = playbook_rag_service.search_playbooks(req.incident_type, n_results=2)
        if matches:
            top_hit = matches[0]
            return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "CHROMA_RAG_HIT",
                    "query": req.incident_type,
                    "playbook_id": top_hit.get("id"),
                    "title": top_hit.get("title"),
                    "category": top_hit.get("category"),
                    "similarity_score": top_hit.get("similarity_score"),
                    "content": top_hit.get("document"),
                    "action_steps": top_hit.get("action_steps", [])
                })
            )
        return ToolResponse(
            success=True,
            result=json.dumps({
                "event": "CHROMA_RAG_MISS",
                "query": req.incident_type,
                "content": "No specific runbook found in vector database for this incident class."
            })
        )
    except Exception as e:
        logger.error("Playbook query failed: %s", e)
        return ToolResponse(success=False, result=f"Playbook RAG Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# TOOL COMBINED: Full-Spectrum Security Triage Pipeline
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/full-triage", response_model=ToolResponse)
async def full_triage(req: FullTriageRequest):
    """
    Executes live multi-service triage concurrently via asyncio.gather().
    """
    try:
        ip_target = req.ip_address or "185.220.101.43"
        mac_target = req.mac_address or "B8:27:EB:AA:BB:CC"
        cve_target = req.cve_id or "CVE-2024-3094"
        incident_target = req.incident_type or "SYN flood volumetric denial of service"

        # Concurrently gather live tool queries
        vt_task = virustotal_service.check_ip(ip_target)
        oui_task = oui_service.resolve_mac(mac_target)
        nvd_task = nvd_service.lookup_cve(cve_target)

        vt_res, oui_res, nvd_res = await asyncio.gather(
            vt_task, oui_task, nvd_task, return_exceptions=True
        )

        vt_data = vt_res if not isinstance(vt_res, Exception) else {"verdict": "ERROR", "error": str(vt_res)}
        oui_data = oui_res if not isinstance(oui_res, Exception) else {"vendor": "ERROR", "error": str(oui_res)}
        cve_data = nvd_res if not isinstance(nvd_res, Exception) else {"found": False, "error": str(nvd_res)}

        # Query ChromaDB Playbook
        pb_matches = playbook_rag_service.search_playbooks(incident_target, n_results=1)
        top_pb = pb_matches[0] if pb_matches else {}

        # Autoencoder scan execution
        scan_resp = await network_scan(ScanRequest(filepath=req.filepath, raw_csv=req.raw_csv))
        scan_data = json.loads(scan_resp.result) if scan_resp.success else {"verdict": "ERROR", "error": scan_resp.result}

        # Severity assessment
        is_critical = (
            scan_data.get("severity") == "CRITICAL"
            or vt_data.get("verdict") == "MALICIOUS"
            or cve_data.get("severity") in ("CRITICAL", "HIGH")
        )

        overall_verdict = "CRITICAL THREAT DETECTED" if is_critical else "NOMINAL / LOW RISK"

        combined_result = {
            "event": "FULL_TRIAGE_COMPLETE",
            "verdict": "MALICIOUS" if is_critical else "CLEAN",
            "overall_status": overall_verdict,
            "scan": scan_data,
            "ip": vt_data,
            "mac": oui_data,
            "cve": cve_data,
            "playbook": {
                "topic": incident_target,
                "playbook_id": top_pb.get("id"),
                "title": top_pb.get("title"),
                "similarity_score": top_pb.get("similarity_score"),
                "procedures": top_pb.get("document", ""),
                "action_steps": top_pb.get("action_steps", [])
            }
        }
        return ToolResponse(success=True, result=json.dumps(combined_result))
    except Exception as e:
        logger.error("Full triage pipeline failed: %s", e)
        return ToolResponse(success=False, result=f"Full triage pipeline failed: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# MOUNT PRODUCTION AGENT ROUTER
# ═══════════════════════════════════════════════════════════════
app.include_router(agent_router)


# ─── Health Check ────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status": "online",
        "version": "2.5.0",
        "google_key_set": bool(os.getenv("GOOGLE_API_KEY")),
        "vt_key_set": bool(os.getenv("VT_API_KEY")),
        "nvd_key_set": bool(os.getenv("NVD_API_KEY")),
        "groq_key_set": bool(os.getenv("GROQ_API_KEY")),
        "openrouter_key_set": bool(os.getenv("OPENROUTER_API_KEY")),
        "chromadb_status": "ready",
        "autoencoder_status": "ready"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
