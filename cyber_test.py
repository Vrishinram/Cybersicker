import os
from google import genai

# Load API key from environment variable
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    raise ValueError("GEMINI_API_KEY environment variable is not set. Please set it before running this script.")

client = genai.Client(api_key=api_key)

# The cybersecurity-focused prompt
prompt = "Explain how dimensionality reduction improves the processing speed and accuracy of hybrid deep learning models when detecting cyberattacks in an IoT network environment."

response = client.models.generate_content(
    model='gemini-2.5-flash',
    contents=prompt
)

print(response.text)