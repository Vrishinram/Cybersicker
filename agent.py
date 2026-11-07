"""
CYBERSICKER — SOC Autonomous Agent CLI
Orchestrated by Ollama (or Google Gemini) with 5 security analysis tools.
"""

from __future__ import annotations

import getpass
import logging
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# 1. Load keys and config from relative .env file if present
load_dotenv(BASE_DIR / ".env")

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama").lower()
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "").strip()

from langchain.agents import create_agent
from tools import (
    ALL_TOOLS,
    network_scanner,
    check_ip_virustotal,
    lookup_mac_address,
    query_cve_database,
    consult_playbook,
)

def build_soc_agent(
    provider: str | None = None,
    model: str | None = None,
    host: str | None = None,
    api_key: str | None = None
):
    selected_provider = (provider or LLM_PROVIDER).lower()

    if selected_provider == "ollama":
        from langchain_ollama import ChatOllama
        target_model = model or OLLAMA_MODEL
        target_host = host or OLLAMA_HOST
        llm = ChatOllama(
            model=target_model,
            base_url=target_host,
            temperature=0,
        )
    elif selected_provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        key = api_key or GOOGLE_API_KEY
        if not key:
            raise ValueError("GOOGLE_API_KEY is required to initialize Gemini Cybersicker agent.")
        llm = ChatGoogleGenerativeAI(
            model=model or "gemini-2.5-flash",
            temperature=0,
            api_key=key,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {selected_provider}. Choose 'ollama' or 'gemini'.")

    return create_agent(
        llm,
        tools=ALL_TOOLS,
        system_prompt="You are Cybersicker, an elite cybersecurity agent designed by Vrishin Ram.K. Use your tools to investigate network threats in this IoT environment and always follow the official playbook rules.",
    )


if __name__ == "__main__":
    print("\n===================================================")
    print("   CYBERSICKER SOC TERMINAL - ONLINE")
    print("   Created by Vrishin Ram.K")
    print(f"   LLM Engine: {LLM_PROVIDER.upper()} (Model: {OLLAMA_MODEL if LLM_PROVIDER == 'ollama' else 'gemini-2.5-flash'})")
    print("   Available Tools: Network Scanner, VirusTotal IP, MAC Lookup, NIST CVE, Playbook")
    print("   Type 'exit' to shut down the agent.")
    print("===================================================\n")

    if LLM_PROVIDER == "gemini" and not GOOGLE_API_KEY:
        if sys.stdin.isatty():
            GOOGLE_API_KEY = getpass.getpass("Please paste your Gemini API Key and press Enter: ")
            os.environ["GOOGLE_API_KEY"] = GOOGLE_API_KEY
        else:
            print("⚠️ Warning: GOOGLE_API_KEY not set. Interactive agent requires a valid key or Ollama.")
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

        if not user_input.strip():
            continue

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
