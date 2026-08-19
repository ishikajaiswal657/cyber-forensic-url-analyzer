🛡️ Cyber Cell Forensic URL Analyzer

A cyber cell investigation tool that detects phishing URLs using domain age, IP geolocation, SSL analysis, and risk scoring — with exportable case reports.

🚀 Key Features
Domain Age Detection: Uses WHOIS lookups to find the creation date and calculate domain maturity.
IP Geolocation: Resolves the domain to its IP address and tracks the host ISP, city, and country.
SSL Verification: Extracts and validates the SSL certificate issuer to check for self-signed or missing encryption.
VirusTotal API Integration: Dynamically queries multi-vendor threat intelligence to cross-check links against live malicious and suspicious signature databases.
Heuristic Risk Scoring: Runs structural checks (URL length, IP usage, phishing keywords, special characters) to compute a final risk score.
Case Report Export: Saves a detailed text report file with a full forensic breakdown for case logs.
Browser Extension: A Chrome/Edge/Firefox extension (Manifest V3) that scans the current tab, any right-clicked link, or a pasted URL — powered by the same live API as the website.
🌐 Web App

Live at: cyber-forensic-url-analyzer-production.up.railway.app

🧩 Browser Extension

The extension/ folder contains a browser extension that talks to the same Flask API as the website — no scanning logic runs in the browser, WHOIS/SSL/VirusTotal checks all happen server-side exactly as they do on the site.

Features:

Auto-scans the current tab's URL when you open the popup
Paste-and-scan any URL manually
Right-click any link on a page → "Scan this link with ShieldCheck"

Install (Chrome/Edge):

Download/clone this repo
Go to chrome://extensions, turn on Developer mode
Click Load unpacked, select the extension folder

Install (Firefox):

Swap extension/manifest.json and extension/manifest.firefox.json (rename accordingly — Firefox only reads manifest.json)
Go to about:debugging#/runtime/this-firefox, click Load Temporary Add-on, select manifest.json

See extension/README.md for full details.

🛠️ Installation & Setup
Clone the Repository:
bash
   git clone [https://github.com/ishikajaiswal657/cyber-forensic-url-analyzer.git](https://github.com/ishikajaiswal657/cyber-forensic-url-analyzer.git)
   cd cyber-forensic-url-analyzer
