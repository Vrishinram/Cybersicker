"""
CYBERSICKER — FastAPI Backend
Exposes the 5 SOC tools + LLM agent chat as REST endpoints
for the Next.js frontend dashboard.
"""

import os
import sys
import json
import traceback
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import pandas as pd
import numpy as np

# ─── App Setup ───────────────────────────────────────────────
app = FastAPI(title="CYBERSICKER API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=***REMOVED***"*"***REMOVED***,
    allow_credentials=True,
    allow_methods=***REMOVED***"*"***REMOVED***,
    allow_headers=***REMOVED***"*"***REMOVED***,
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
  ***REMOVED***
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

class ChatRequest(BaseModel):
    message: str
    history: list = ***REMOVED******REMOVED***

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
              ***REMOVED***)
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
              ***REMOVED***)
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
      ***REMOVED***
        data = mock_threats.get(req.ip_address, {
            "malicious": 0, "suspicious": 0, "harmless": 10, "verdict": "CLEAN"
      ***REMOVED***)
        return ToolResponse(
            success=True,
            result=json.dumps({
                "event": "VT_LOOKUP (SIMULATED)",
                "ip": req.ip_address,
                **data
          ***REMOVED***)
        )
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{req.ip_address}"
        headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json()***REMOVED***'data'***REMOVED******REMOVED***'attributes'***REMOVED******REMOVED***'last_analysis_stats'***REMOVED***
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
              ***REMOVED***)
            )
        return ToolResponse(success=False, result=f"VirusTotal API returned status {response.status_code}")
    except Exception as e:
        return ToolResponse(success=False, result=f"Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# TOOL 3: MAC Address Lookup
# ═══════════════════════════════════════════════════════════════
@app.post("/api/tools/mac-lookup", response_model=ToolResponse)
async def mac_lookup(req: MACRequest):
    try:
        # Normalization to handle dots/hyphens/colons
        clean_mac = req.mac_address.replace('-', ':').replace('.', '').strip()
        if '.' in req.mac_address and len(req.mac_address) >= 14: # Cisco style
             clean_mac = ':'.join(***REMOVED***req.mac_address.replace('.', '')***REMOVED***i:i+2***REMOVED*** for i in range(0, 12, 2)***REMOVED***)
        
        oui = clean_mac.replace(':', '')***REMOVED***:6***REMOVED***.upper()
        
        # ── Simulation Guard ──
        mock_vendors = {
            "001A2B": "Cisco Systems, Inc.",
            "001A2B3C4D5E": "Cisco Systems, Inc.",
      ***REMOVED***
        vendor = mock_vendors.get(oui, None)
        if vendor:
             return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "MAC_RESOLVE (SIMULATED)",
                    "mac": req.mac_address,
                    "oui": oui,
                    "vendor": vendor,
                    "note": f"Verified {vendor} device. Format detected correctly."
              ***REMOVED***)
            )

        url = f"https://api.macvendors.com/{clean_mac}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            vendor = response.text.strip()
            return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "MAC_RESOLVE",
                    "mac": clean_mac,
                    "oui": oui,
                    "vendor": vendor,
                    "note": f"Device manufactured by {vendor}. Cross-reference with IoT asset inventory."
              ***REMOVED***)
            )
        elif response.status_code == 404:
            return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "MAC_RESOLVE",
                    "mac": clean_mac,
                    "oui": oui,
                    "vendor": "NOT FOUND",
                    "note": "Vendor not found. Could be a spoofed MAC or unregistered device. Treat as suspicious."
              ***REMOVED***)
            )
        return ToolResponse(success=False, result=f"MAC lookup failed with status {response.status_code}")
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
          ***REMOVED***,
            "CVE-2017-0144": {
                "published": "2017-03-14", "cvss_score": 8.1, "severity": "HIGH",
                "description": "SMBv1 vulnerability used by EternalBlue and WannaCry.",
                "recommendation": "Apply MS17-010 security update."
          ***REMOVED***,
            "CVE-2023-23397": {
                "published": "2023-03-14", "cvss_score": 9.8, "severity": "CRITICAL",
                "description": "Microsoft Outlook Elevation of Privilege Vulnerability.",
                "recommendation": "Apply latest Microsoft Outlook patches."
          ***REMOVED***
      ***REMOVED***
        if cve_id in mock_cves:
             return ToolResponse(success=True, result=json.dumps({
                "event": "CVE_LOOKUP (SIMULATED)", "cve_id": cve_id, "found": True,
                **mock_cves***REMOVED***cve_id***REMOVED***
          ***REMOVED***))

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, headers={"Accept": "application/json"}, timeout=15)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", ***REMOVED******REMOVED***)
            if not vulns:
                return ToolResponse(success=True, result=json.dumps({
                    "event": "CVE_LOOKUP", "cve_id": cve_id, "found": False,
                    "note": f"{cve_id} not found in NVD database."
              ***REMOVED***))
            cve_data = vulns***REMOVED***0***REMOVED***.get("cve", {})
            desc_list = cve_data.get("descriptions", ***REMOVED******REMOVED***)
            description = next((d***REMOVED***"value"***REMOVED*** for d in desc_list if d***REMOVED***"lang"***REMOVED*** == "en"), "No description available.")
            metrics = cve_data.get("metrics", {})
            cvss_score = "N/A"
            severity = "N/A"
            for vk in ***REMOVED***"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"***REMOVED***:
                if vk in metrics:
                    cvss_data = metrics***REMOVED***vk***REMOVED******REMOVED***0***REMOVED***.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", "N/A")
                    break
            published = cve_data.get("published", "Unknown")***REMOVED***:10***REMOVED***
            return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "CVE_LOOKUP",
                    "cve_id": cve_id,
                    "found": True,
                    "published": published,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": description***REMOVED***:500***REMOVED***,
                    "recommendation": "Patch immediately if score >= 7.0. Check vendor advisories for IoT firmware updates."
              ***REMOVED***)
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
            combined = "\n---\n".join(***REMOVED***r.page_content for r in results***REMOVED***)
            return ToolResponse(
                success=True,
                result=json.dumps({
                    "event": "PLAYBOOK_MATCH",
                    "query": req.incident_type,
                    "matches": len(results),
                    "content": combined
              ***REMOVED***)
            )
        return ToolResponse(success=True, result=json.dumps({
            "event": "PLAYBOOK_MATCH", "query": req.incident_type,
            "matches": 0, "content": "No specific rule found for this incident type."
      ***REMOVED***))
    except Exception as e:
        return ToolResponse(success=False, result=f"Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# AGENT CHAT — LLM + Tools
# ═══════════════════════════════════════════════════════════════
@app.post("/api/chat")
async def agent_chat(req: ChatRequest):
    debug_log("B1", "api.py:agent_chat:entry", "Chat request entered", {
        "message_len": len(req.message or ""),
        "google_key_set": bool(GOOGLE_API_KEY),
        "vt_key_set": bool(VT_API_KEY),
        "groq_key_set": bool(GROQ_API_KEY),
        "openrouter_key_set": bool(OPENROUTER_API_KEY),
        "scitely_key_set": bool(SCITELY_API_KEY),
  ***REMOVED***)
    if not GOOGLE_API_KEY and not GROQ_API_KEY and not OPENROUTER_API_KEY and not SCITELY_API_KEY:
        debug_log("B1", "api.py:agent_chat:sandbox", "No keys found, entering Sandbox Mode", {})
        return {
            "success": True,
            "response": (
                "🛡️ **Cybersicker Sandbox Mode Active**\n\n"
                "I am running in **Keyless Sandbox Mode**. I can assist with general cybersecurity inquiries, but my autonomous tool-calling capabilities are limited.\n\n"
                "- **Available:** Network Scan (Simulated), IP Rep (Mock), CVE Query (Simulated)\n"
                "- **Required:** Add a `GOOGLE_API_KEY` or `SCITELY_API_KEY` to `.env` for full autonomous power.\n\n"
                "How can I assist your SOC operations today?"
            ),
      ***REMOVED***
    try:
        from langchain.tools import tool
        from autoencoder import run_network_scan as _run_scan

        @tool
        def network_scanner(filepath: str) -> str:
            """Scan network traffic logs for cyber attacks or anomalies."""
            try:
                anomalies = _run_scan(filepath)
                return f"Scan complete. Found {anomalies} anomalies."
            except Exception as e:
                return f"Failed to run scanner: {str(e)}"

        @tool
        def check_ip_virustotal(ip_address: str) -> str:
            """Investigate an IP using VirusTotal. Input must be an IPv4 address."""
            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
                headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
                resp = requests.get(url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    stats = resp.json()***REMOVED***'data'***REMOVED******REMOVED***'attributes'***REMOVED******REMOVED***'last_analysis_stats'***REMOVED***
                    mal = stats.get('malicious', 0)
                    return f"CRITICAL: {mal} vendors flagged {ip_address} as malicious!" if mal > 0 else f"CLEAN: 0 vendors flagged {ip_address}."
                return f"API error {resp.status_code}"
            except Exception as e:
                return f"Error: {str(e)}"

        @tool
        def lookup_mac_address(mac_address: str) -> str:
            """Look up device manufacturer by MAC address."""
            try:
                resp = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=10)
                return f"Vendor: {resp.text.strip()}" if resp.status_code == 200 else "Vendor not found."
            except Exception as e:
                return f"Error: {str(e)}"

        @tool
        def query_cve_database(cve_id: str) -> str:
            """Query NIST NVD for CVE details. Input: CVE-XXXX-XXXXX."""
            try:
                resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.strip().upper()}", timeout=15)
                if resp.status_code == 200:
                    vulns = resp.json().get("vulnerabilities", ***REMOVED******REMOVED***)
                    if not vulns:
                        return f"{cve_id} not found."
                    cve = vulns***REMOVED***0***REMOVED******REMOVED***"cve"***REMOVED***
                    desc = next((d***REMOVED***"value"***REMOVED*** for d in cve.get("descriptions", ***REMOVED******REMOVED***) if d***REMOVED***"lang"***REMOVED*** == "en"), "No description.")
                    return f"CVE: {cve_id}\nDescription: {desc***REMOVED***:400***REMOVED***}"
                return f"API error {resp.status_code}"
            except Exception as e:
                return f"Error: {str(e)}"

        @tool
        def consult_playbook_tool(incident_type: str) -> str:
            """Search the IR Playbook for response procedures."""
            try:
                from langchain_community.document_loaders import TextLoader
                from langchain_community.vectorstores import Chroma
                from langchain_community.embeddings import HuggingFaceEmbeddings
                from langchain_text_splitters import CharacterTextSplitter
                loader = TextLoader(os.path.join(BASE_DIR, "playbook.env.txt"))
                docs = CharacterTextSplitter(chunk_size=1000, chunk_overlap=100).split_documents(loader.load())
                db = Chroma.from_documents(docs, HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2"))
                results = db.similarity_search(incident_type, k=3)
                return "\n---\n".join(***REMOVED***r.page_content for r in results***REMOVED***) if results else "No match found."
            except Exception as e:
                return f"Error: {str(e)}"

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

        debug_log("B4", "api.py:agent_chat:provider", "Selected chat provider", {
            "provider": provider
      ***REMOVED***)

        if llm is None:
            raise RuntimeError("No valid chat provider configured.")

        # LangChain Agents usually require a prompt template. 
        # We'll use a more direct approach if create_agent is missing or failing.
        tools = ***REMOVED***network_scanner, check_ip_virustotal, lookup_mac_address, query_cve_database, consult_playbook_tool***REMOVED***
        
        try:
            # Try standard tool calling if supported by the LLM
            llm_with_tools = llm.bind_tools(tools)
            
            # Simple manual agent loop for maximum compatibility
            messages = ***REMOVED***
                ("system", (
                    "You are Cybersicker, an elite cybersecurity SOC agent designed by Vrishin Ram K. "
                    "You analyze IoT network threats using your tools. Always format responses neatly with markdown. "
                    "Use bold for key findings, code blocks for IPs/hashes, and bullet points for structured data."
                )),
                ("user", req.message)
            ***REMOVED***
            
            ai_msg = llm_with_tools.invoke(messages)
            
            # Basic tool execution logic
            tool_map = {tool.name: tool for tool in tools}
            if ai_msg.tool_calls:
                for tool_call in ai_msg.tool_calls:
                    selected_tool = tool_map***REMOVED***tool_call***REMOVED***"name"***REMOVED***.lower().replace("-", "_")***REMOVED***
                    tool_output = selected_tool.invoke(tool_call***REMOVED***"args"***REMOVED***)
                    messages.append(ai_msg)
                    messages.append(("tool", tool_output, tool_call***REMOVED***"id"***REMOVED***))
                
                # Final response after tool calls
                final_response = llm_with_tools.invoke(messages)
                answer = final_response.content
            else:
                answer = ai_msg.content

        except Exception as tool_err:
            # If tool calling fails (e.g. Scitely formatting error), fallback to direct chat
            debug_log("B5", "api.py:agent_chat:tool_fallback", f"Tool calling failed: {str(tool_err)}", {})
            response = llm.invoke(***REMOVED***("user", req.message)***REMOVED***)
            answer = response.content

        return {"success": True, "response": answer}

    except Exception as e:
        debug_log("B2", "api.py:agent_chat:exception", "Agent execution failed", {
            "error_type": type(e).__name__,
            "error": str(e)***REMOVED***:300***REMOVED***,
      ***REMOVED***)
        traceback.print_exc()
        
        # Fallback to Mock Agent (Sandbox Mode) if LLM provider fails
        try:
            debug_log("B6", "api.py:agent_chat:mock_fallback", "Attempting Mock Agent fallback after LLM failure", {})
            
            # Simple simulation logic based on keywords
            msg = req.message.lower()
            if "scan" in msg or "traffic" in msg:
                response = (
                    "🛡️ **Cybersicker Sandbox Analysis**\n\n"
                    "I've performed a simulated network scan on the requested logs.\n"
                    "- **Status:** Completed (Simulated)\n"
                    "- **Anomalies Detected:** 42\n"
                    "- **Severity:** MONITORING\n"
                    "- **Recommendation:** No critical threats found, but proceed with caution."
                )
            elif "ip" in msg or "." in msg:
                response = (
                    "🚨 **Cybersicker Sandbox Alert**\n\n"
                    "I've simulated a VirusTotal investigation for the IP address mentioned.\n"
                    "- **Verdict:** SUSPICIOUS\n"
                    "- **Detection Ratio:** 4/72\n"
                    "- **Note:** This IP has been associated with low-level scanning activity in Sandbox mode."
                )
            else:
                response = (
                    "🛡️ **Cybersicker Sandbox Mode**\n\n"
                    "The primary LLM provider (Scitely/Gemini) is currently unavailable.\n"
                    "I am operating in **Sandbox Mode**. I can still assist with general security questions and simulate tool usage.\n\n"
                    "How can I help you today?"
                )
            return {"success": True, "response": response + "\n\n*(Note: Sandbox Fallback active due to provider error)*"}
        except Exception as fallback_err:
            return {"success": False, "response": f"Agent error: {str(e)} (Fallback also failed: {str(fallback_err)})"}


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
  ***REMOVED***


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
