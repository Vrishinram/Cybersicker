import requests
import os
import json
from dotenv import load_dotenv

load_dotenv()

def test_api(url, model, key):
    print(f"\n--- Testing URL: {url} | Model: {model} ---")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
  ***REMOVED***
    payload = {
        "model": model,
        "messages": ***REMOVED***{"role": "user", "content": "hi"}***REMOVED***,
        "stream": False
  ***REMOVED***
    try:
        resp = requests.post(f"{url}/chat/completions", headers=headers, json=payload, timeout=15)
        print(f"Status Code: {resp.status_code}")
        data = resp.json()
        print(f"Response Body: {json.dumps(data, indent=2)}")
        return data
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    key = os.environ.get("SCITELY_API_KEY")
    base_urls = ***REMOVED***"https://api.scitely.ai/v1", "https://api.scitely.com/v1"***REMOVED***
    models = ***REMOVED***"qwen3-32b", "qwen3-coder-plus", "gpt-4o-mini"***REMOVED***
    
    for url in base_urls:
        for model in models:
            test_api(url, model, key)
