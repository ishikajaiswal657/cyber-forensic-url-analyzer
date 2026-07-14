
import os
import requests
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

print(f"Key loaded: {'YES - ' + VT_API_KEY[:6] + '...' if VT_API_KEY else 'NO - key is None or empty'}")

if not VT_API_KEY:
    print("STOP: Fix your .env file first. VT_API_KEY is not loading.")
else:
    url = "https://testsafebrowsing.appspot.com/s/malware.html"
    headers = {"x-apikey": VT_API_KEY}

    print(f"\nSubmitting URL to VirusTotal...")
    resp = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
        timeout=10
    )
    print(f"Status code: {resp.status_code}")
    print(f"Response body: {resp.text[:500]}")