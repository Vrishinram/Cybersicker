"""
CYBERSICKER — SOC Autonomous Agent CLI
Orchestrated by Google Gemini LLM with 5 security analysis tools.
"""

from __future__ import annotations

import getpass
import logging
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# 1. Load keys from relative .env file if present
load_dotenv(BASE_DIR / ".env")

# 2. Check API keys
google_key = os.environ.get("GOOGLE_API_KEY")
if not google_key and sys.stdin.isatty():
    print("\n🚨 Google API Key not found in environment or .env file!")
    google_key = getpass.getpass("Please paste your Gemini API Key and press Enter: ")
    os.environ["GOOGLE_API_KEY"] = google_key

from langchain.agents import create_agent
from langchain_google_genai import ChatGoogleGenerativeAI

from tools import (
    ALL_TOOLS,
    network_scanner,
    check_ip_virustotal,
    lookup_mac_address,
    query_cve_database,
    consult_playbook,
)

def build_soc_agent(api_key: str | None = None):
    key = api_key or os.environ.get("GOOGLE_API_KEY")
    if not key:
        raise ValueError("GOOGLE_API_KEY is required to initialize Cybersicker agent.")
    
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        temperature=0,
        api_key=key,
    )
    return create_agent(
        llm,
        tools=ALL_TOOLS,
        system_prompt="You are Cybersicker, an elite cybersecurity agent designed by Vrishin Ram.K. Use your tools to investigate network threats in this IoT environment and always follow the official playbook rules.",
    )


if __name__ == "__main__":
    print("\n===================================================")
    print("   CYBERSICKER SOC TERMINAL - ONLINE")
    print("   Created by Vrishin Ram.K")
    print("   Available Tools: Network Scanner, VirusTotal IP, MAC Lookup, NIST CVE, Playbook")
    print("   Type 'exit' to shut down the agent.")
    print("===================================================\n")

    if not os.environ.get("GOOGLE_API_KEY"):
        print("⚠️ Warning: GOOGLE_API_KEY not set. Interactive agent requires a valid key.")
        sys.exit(1)

    agent = build_soc_agent()

    while True:
        try:
            user_input = input("Cybersicker > ")
        except (KeyboardInterrupt, EOFError):
            print("\nShutting down Cybersicker defenses. Goodbye!")
            break

        if user_input.lower() in ["exit", "quit"]:
            print("Shutting down Cybersicker defenses. Goodbye!")
            break

        try:
            response = agent.invoke({
                "messages": [
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
            print(f"\n❌ Error: Cybersicker encountered an issue: {e}\n")