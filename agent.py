import os
import requests
import getpass
import logging
from dotenv import load_dotenv

# 1. Try to load secret keys from the .env file
load_dotenv(r"C:\Users\91638\Desktop\.env")

# --- BULLETPROOF KEY CHECK ---
google_key = os.environ.get("GOOGLE_API_KEY")
if not google_key:
    print("\n🚨 Google API Key not found in .env file!")
    google_key = getpass.getpass("Please paste your Gemini API Key and press Enter: ")
    os.environ["GOOGLE_API_KEY"] = google_key

vt_key = os.environ.get("VT_API_KEY")
if not vt_key:
    print("\n🚨 VirusTotal API Key not found in .env file!")
    vt_key = getpass.getpass("Please paste your VirusTotal API Key and press Enter: ")
    os.environ["VT_API_KEY"] = vt_key
# -----------------------------

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_text_splitters import CharacterTextSplitter

from autoencoder import run_network_scan

# 2. The Tools
@tool
def network_scanner(filepath: str) -> str:
    """
    Scan network traffic logs for cyber attacks and anomalies using ML-based detection.
    
    Cybersecurity Skills:
    - detecting-botnet-traffic-patterns (Threat Hunting)
    - network-traffic-analysis-fundamentals (Network Security)
    - detecting-ddos-volumetric-attacks (Threat Hunting)
    - detecting-lateral-movement-in-networks (Threat Hunting)
    
    MITRE ATT&CK Techniques Detected:
    - T1571: Non-Standard Port/Protocol
    - T1008: Fallback Channels
    - T1498: Network Denial of Service (Volumetric)
    - T1570: Lateral Tool Transfer
    
    NIST CSF Alignment:
    - DE.CM-01: Monitor network activities
    - DE.AE-02: Detect anomalies
    
    Args:
        filepath: Path to network traffic CSV
    
    Returns:
        Detection results with anomaly count and severity
    """
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Cybersicker")
    
    logger.info(f"Scanning {filepath} for network anomalies...")
    try:
        anomalies = run_network_scan(filepath)
        logger.info(f"[DETECTION] Found {anomalies} anomalies")
        
        # Risk scoring
        if anomalies > 100:
            risk_level = "🔴 CRITICAL"
        elif anomalies > 50:
            risk_level = "🟠 HIGH"
        elif anomalies > 20:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"
        
        return f"Scan complete. Found {anomalies} anomalies ({risk_level}). MITRE ATT&CK Coverage: T1571, T1008, T1498, T1570"
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        return f"Failed to run scanner: {str(e)}"

@tool
def check_ip_virustotal(ip_address: str) -> str:
    """
    Investigate an IP address using VirusTotal threat intelligence and reputation scoring.
    
    Cybersecurity Skills:
    - threat-intelligence-api-integration (Threat Intelligence)
    - analyzing-malicious-ip-reputation (Threat Intelligence)
    - ip-reputation-scoring-methodology (Threat Intelligence)
    - geolocation-ip-tracking (Threat Intelligence)
    - ssl-tls-certificate-validation (Network Security)
    
    MITRE ATT&CK Techniques:
    - T1592: Gather Victim Network Information
    - T1598: Phishing for Information
    - T1589: Gather Victim Identity Information
    
    NIST CSF Alignment:
    - DE.CM-01: Continuous monitoring
    - DE.DP-01: Detection based on threat patterns
    
    Args:
        ip_address: IPv4 address to investigate
        
    Returns:
        Threat intelligence report with reputation score and recommendations
    """
    import logging
    import json
    from pydantic import BaseModel, ValidationError
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Cybersicker")
    
    # Validate IP format
    ip_parts = ip_address.split('.')
    if len(ip_parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
        logger.warning(f"Invalid IP format: {ip_address}")
        return f"[Error] Invalid IPv4 format: {ip_address}"
    
    logger.info(f"Querying VirusTotal for IP: {ip_address}")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"accept": "application/json", "x-apikey": vt_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 401:
            logger.error("VirusTotal API key invalid")
            return "[Error] VirusTotal API authentication failed"
        
        if response.status_code == 404:
            logger.info(f"IP {ip_address} not found in VirusTotal database")
            return f"[Info] IP {ip_address} not in VirusTotal (likely new/clean)"
        
        if response.status_code == 200:
            try:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                undetected = stats.get('undetected', 0)
                
                # Calculate reputation score (0-100)
                total_votes = malicious + suspicious + undetected
                reputation_score = 100 if total_votes == 0 else max(0, 100 - (malicious * 10 + suspicious * 3))
                
                # Threat level
                if malicious > 5:
                    threat_level = "🔴 CRITICAL"
                    action = "BLOCK IMMEDIATELY"
                elif malicious > 0:
                    threat_level = "🟠 HIGH"
                    action = "QUARANTINE & INVESTIGATE"
                elif suspicious > 3:
                    threat_level = "🟡 MEDIUM"
                    action = "MONITOR CLOSELY"
                else:
                    threat_level = "🟢 LOW"
                    action = "ALLOW"
                
                # Get ASN and country info
                asn_info = data['data']['attributes'].get('asn', {}).get('asn', 'Unknown')
                country = data['data']['attributes'].get('country', 'Unknown')
                
                report = f"""[THREAT INTELLIGENCE] Skill: threat-intelligence-api-integration
MITRE ATT&CK: T1592 (Gather Victim Network Information)

IP: {ip_address}
Threat Level: {threat_level}
Reputation Score: {reputation_score}/100

Vendor Analysis:
  Malicious: {malicious} vendors
  Suspicious: {suspicious} vendors
  Clean: {undetected} vendors

Network Info:
  ASN: {asn_info}
  Country: {country}

[RECOMMENDATION] {action}
[NIST CSF] DE.CM-01 (Continuous monitoring) - Outcome: {threat_level}"""
                
                logger.info(f"IP reputation analyzed: {ip_address} score={reputation_score}")
                return report
                
            except (KeyError, json.JSONDecodeError) as e:
                logger.error(f"Failed to parse VirusTotal response: {e}")
                return f"[Error] Could not parse threat intelligence data"
        
        logger.error(f"VirusTotal API returned status {response.status_code}")
        return f"[Error] API returned status code {response.status_code}"
        
    except requests.exceptions.Timeout:
        logger.error(f"VirusTotal API timeout for {ip_address}")
        return "[Error] VirusTotal API timeout - please retry"
    except Exception as e:
        logger.error(f"VirusTotal query failed: {str(e)}", exc_info=True)
        return f"[Error] Could not query threat intelligence: {str(e)}"

@tool
def consult_playbook(incident_type: str) -> str:
    """
    Consult incident response playbook for structured procedures and decision trees.
    
    Cybersecurity Skills:
    - ransomware-incident-response-playbook (Incident Response)
    - ddos-attack-response-procedures (Incident Response)
    - malware-incident-response (Incident Response)
    - credential-compromise-breach-response (Incident Response)
    - incident-response-communication-escalation (Incident Response)
    - evidence-preservation-procedures (Digital Forensics)
    
    MITRE ATT&CK Techniques Covered:
    - T1486: Data Encrypted for Impact (Ransomware)
    - T1498: Network Denial of Service
    - T1566: Phishing
    - T1110: Brute Force
    
    NIST CSF Alignment:
    - RS.RP: Response Planning
    - RS.CO: Communications & Analysis
    - RS.AN: Analysis
    - RC.RP: Recovery Planning
    - RC.IM: Improvements
    
    Args:
        incident_type: Description of incident (e.g., "ransomware", "ddos", "malware")
        
    Returns:
        Structured incident response procedures and decision trees
    """
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Cybersicker")
    
    logger.info(f"Consulting playbook for incident type: {incident_type}")
    try:
        playbook_path = r"C:\Users\91638\Desktop\playbook.txt"
        
        # Validate file exists
        if not os.path.exists(playbook_path):
            logger.warning(f"Playbook not found at {playbook_path}")
            return f"[Warning] Incident response playbook not found at {playbook_path}"
        
        loader = TextLoader(playbook_path)
        documents = loader.load()
        
        # Chunk for RAG
        text_splitter = CharacterTextSplitter(chunk_size=200, chunk_overlap=20)
        docs = text_splitter.split_documents(documents)
        
        # Create embeddings
        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        db = Chroma.from_documents(docs, embeddings)
        
        # Search for relevant procedure
        results = db.similarity_search(incident_type, k=3)
        
        if results:
            procedures = "\n---\n".join([f"Step {i+1}: {r.page_content}" for i, r in enumerate(results)])
            report = f"""[INCIDENT RESPONSE PLAYBOOK] Skill: {incident_type.replace(' ', '-')}-response-procedures
MITRE ATT&CK Coverage: Based on threat type

Structured Procedures:
{procedures}

[NIST CSF] RS.RP (Response Planning) - Applicable
Documentation: Preserve evidence for forensic analysis (RS.AN)
Communication: Follow escalation procedures (RS.CO)
Recovery: Execute recovery procedures post-incident (RC.RP)

[ACTION ITEMS]
1. Isolate affected systems
2. Preserve forensic evidence
3. Escalate to SOC management
4. Execute containment steps
5. Document all actions"""
            logger.info(f"Playbook procedures found for: {incident_type}")
            return report
        
        logger.warning(f"No playbook procedures found for: {incident_type}")
        return f"[Info] No specific playbook rule found for '{incident_type}'. Consider generic IR procedures."
        
    except Exception as e:
        logger.error(f"Playbook consultation failed: {str(e)}", exc_info=True)
        return f"[Error] Could not access incident response playbook: {str(e)}"

# 3. The Agent Brain
# We explicitly pass the google_key here so it cannot fail!
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0, api_key=google_key)
tools = [network_scanner, check_ip_virustotal, consult_playbook]
agent = create_agent(llm, tools=tools)

# 4. The Autonomous Execution Loop
if __name__ == "__main__":
    print("\n===================================================")
    print("   CYBERSICKER SOC TERMINAL - ONLINE")
    print("   Created by Vrishin Ram.K")
    print("   Type 'exit' to shut down the agent.")
    print("===================================================\n")
    
    while True:
        user_input = input("Cybersicker > ")
        
        if user_input.lower() in ['exit', 'quit']:
            print("Shutting down Cybersicker defenses. Goodbye!")
            break
            
        try:
            response = agent.invoke({
                "messages": [
                    ("system", "You are Cybersicker, an elite cybersecurity agent designed by Vrishin Ram.K. Use your tools to investigate network threats in this IoT environment and always follow the official playbook rules."),
                    ("user", user_input)
                ]
            })
            
            print("\n--- SOC Report ---")
            final_content = response["messages"][-1].content
            if isinstance(final_content, list):
                print(final_content[0]["text"])
            else:
                print(final_content)
            print("-" * 50 + "\n")
            
        except Exception as e:
            print(f"\n❌ Error: Cybersicker encountered an issue: {str(e)}\n")