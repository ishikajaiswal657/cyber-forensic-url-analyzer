# 🛡️ Cyber Cell Forensic URL Analyzer

A cyber cell investigation tool that detects phishing URLs using domain age, IP geolocation, SSL analysis, and risk scoring — with exportable case reports.

---

## 🚀 Key Features

* **Domain Age Detection:** Uses WHOIS lookups to find the creation date and calculate domain maturity.
* **IP Geolocation:** Resolves the domain to its IP address and tracks the host ISP, city, and country.
* **SSL Verification:** Extracts and validates the SSL certificate issuer to check for self-signed or missing encryption.
* **VirusTotal API Integration:** Dynamically queries multi-vendor threat intelligence to cross-check links against live malicious and suspicious signature databases.
* **Heuristic Risk Scoring:** Runs structural checks (URL length, IP usage, phishing keywords, special characters) to compute a final risk score.
* **Case Report Export:** Saves a detailed text report file with a full forensic breakdown for case logs.

---

## 🛠️ Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/ishikajaiswal657/cyber-forensic-url-analyzer.git](https://github.com/ishikajaiswal657/cyber-forensic-url-analyzer.git)
   cd cyber-forensic-url-analyzer
