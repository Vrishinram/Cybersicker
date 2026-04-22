from google import genai

# Passing the key directly into the client
client = genai.Client(api_key="[REDACTED_LEAKED_API_KEY]")

# The cybersecurity-focused prompt
prompt = "Explain how dimensionality reduction improves the processing speed and accuracy of hybrid deep learning models when detecting cyberattacks in an IoT network environment."

response = client.models.generate_content(
    model='gemini-2.5-flash',
    contents=prompt
)

print(response.text)