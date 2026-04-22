import os
import requests
import getpass
from dotenv import load_dotenv

# 1. Try to load secret keys from the .env file
load_dotenv(r"C:\Users\91638\Desktop\.env")

# --- BULLETPROOF KEY CHECK ---
google_key = os.environ.get("GOOGLE_API_KEY")
if not google_key:
    print("\n***REMOVED***🚨***REMOVED*** Google API Key not found in .env file!")
    google_key = getpass.getpass("Please paste your Gemini API Key and press Enter: ")
    os.environ***REMOVED***"GOOGLE_API_KEY"***REMOVED*** = google_key

vt_key = os.environ.get("VT_API_KEY")
if not vt_key:
    print("\n***REMOVED***🚨***REMOVED*** VirusTotal API Key not found in .env file!")
    vt_key = getpass.getpass("Please paste your VirusTotal API Key and press Enter: ")
    os.environ***REMOVED***"VT_API_KEY"***REMOVED*** = vt_key
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
    """Scan network traffic logs for cyber attacks or anomalies."""
    print(f"\n***REMOVED***Cybersicker***REMOVED*** Scanning {filepath}...")
    try:
        anomalies = run_network_scan(filepath)
        return f"Scan complete. Found {anomalies} anomalies."
    except Exception as e:
        return f"Failed to run scanner: {str(e)}"

@tool
def check_ip_virustotal(ip_address: str) -> str:
    """Investigate an IP address using VirusTotal threat intelligence. Input MUST be an IPv4 address string."""
    print(f"\n***REMOVED***Cybersicker***REMOVED*** Querying VirusTotal for IP: {ip_address}...")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"accept": "application/json", "x-apikey": vt_key} # Using the checked key
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()***REMOVED***'data'***REMOVED******REMOVED***'attributes'***REMOVED******REMOVED***'last_analysis_stats'***REMOVED***
            malicious = stats.get('malicious', 0)
            if malicious > 0:
                return f"CRITICAL: {malicious} security vendors flagged {ip_address} as malicious!"
            return f"CLEAN: 0 vendors flagged {ip_address} as malicious."
        return f"Error: API returned status code {response.status_code}"
    except Exception as e:
        return f"Error connecting to VirusTotal: {str(e)}"

@tool
def consult_playbook(incident_type: str) -> str:
    """Use this tool to read the official Incident Response Playbook to see what actions to take. Pass a brief description of the incident as the input."""
    print(f"\n***REMOVED***Cybersicker***REMOVED*** Searching the IR Playbook for: {incident_type}...")
    try:
        loader = TextLoader(r"C:\Users\91638\Desktop\playbook.txt")
        documents = loader.load()
        text_splitter = CharacterTextSplitter(chunk_size=200, chunk_overlap=20)
        docs = text_splitter.split_documents(documents)
        
        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        db = Chroma.from_documents(docs, embeddings)
        
        results = db.similarity_search(incident_type, k=1)
        if results:
            return f"Official Playbook Rule: {results***REMOVED***0***REMOVED***.page_content}"
        return "No specific rule found for this incident type."
    except Exception as e:
        return f"Error reading playbook: {str(e)}"

# 3. The Agent Brain
# We explicitly pass the google_key here so it cannot fail!
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0, api_key=google_key)
tools = ***REMOVED***network_scanner, check_ip_virustotal, consult_playbook***REMOVED***
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
        
        if user_input.lower() in ***REMOVED***'exit', 'quit'***REMOVED***:
            print("Shutting down Cybersicker defenses. Goodbye!")
            break
            
        try:
            response = agent.invoke({
                "messages": ***REMOVED***
                    ("system", "You are Cybersicker, an elite cybersecurity agent designed by Vrishin Ram.K. Use your tools to investigate network threats in this IoT environment and always follow the official playbook rules."),
                    ("user", user_input)
                ***REMOVED***
          ***REMOVED***)
            
            print("\n--- SOC Report ---")
            final_content = response***REMOVED***"messages"***REMOVED******REMOVED***-1***REMOVED***.content
            if isinstance(final_content, list):
                print(final_content***REMOVED***0***REMOVED******REMOVED***"text"***REMOVED***)
            else:
                print(final_content)
            print("-" * 50 + "\n")
            
        except Exception as e:
            print(f"\n***REMOVED***Error***REMOVED*** Cybersicker encountered an issue: {str(e)}\n")