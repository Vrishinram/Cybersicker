import requests
import os
import json
from dotenv import load_dotenv

load_dotenv()

key = os.environ.get("SCITELY_API_KEY")
url = "https://api.scitely.com/v1/models"

try:
    resp = requests.get(url, headers={"Authorization": f"Bearer {key}"})
    print(f"Status: {resp.status_code}")
    with open("scitely_models.json", "w") as f:
        f.write(resp.text)
    print("Saved to scitely_models.json")
except Exception as e:
    print(f"Error: {e}")
