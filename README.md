# 🛡️ ShieldCheck — Cyber Cell Forensic URL & Email Analyzer

A phishing investigation tool that detects malicious URLs and suspicious emails using domain age, IP geolocation, SSL analysis, VirusTotal threat intelligence, and heuristic risk scoring — with exportable case reports and a browser extension.

---

## 🚀 Key Features

- **Domain Age Detection** – WHOIS lookups to find domain creation date and calculate domain maturity.
- **IP Geolocation** – Resolves the domain to its IP address and tracks host ISP, city, and country.
- **SSL Verification** – Extracts and validates the SSL certificate issuer to flag self-signed or missing encryption.
- **VirusTotal API Integration** – Queries multi-vendor threat intelligence to cross-check URLs against live malicious/suspicious signature databases.
- **Email (.eml) Analysis** – Parses email headers and content to detect phishing indicators in `.eml` files.
- **Heuristic Risk Scoring** – Structural checks (URL length, IP usage, phishing keywords, special characters, HTTPS presence) to compute a final risk score.
- **Case Report Export** – Saves a detailed text report with a full forensic breakdown for case logs.
- **Browser Extension** – Chrome/Edge/Firefox extension (Manifest V3) that scans the current tab, any right-clicked link, or a pasted URL — powered by the same live API as the website.

---

## 🌐 Web App

Live at: https://shieldcheck-gih5.onrender.com

---

## 🧩 Browser Extension

Download `shieldcheck.zip` from this repo. It contains a browser extension that talks to the same Flask API as the website — no scanning logic runs in the browser; WHOIS/SSL/VirusTotal checks all happen server-side exactly as they do on the site.

**Features:**
- Auto-scans the current tab's URL when you open the popup
- Paste-and-scan any URL manually
- Right-click any link on a page → "Scan this link with ShieldCheck"

**Install (Chrome/Edge):**
1. Download `shieldcheck.zip` and unzip it — you'll get a folder called `extension`
2. Go to `chrome://extensions`, turn on Developer mode
3. Click Load unpacked, select the unzipped `extension` folder

**Install (Firefox):**
1. Unzip `shieldcheck.zip`. Inside, swap `manifest.json` and `manifest.firefox.json` (rename accordingly — Firefox only reads `manifest.json`)
2. Go to `about:debugging#/runtime/this-firefox`, click Load Temporary Add-on, select `manifest.json`

---

## 📧 Email Analysis

Upload or point the tool at a `.eml` file to scan headers and content for phishing indicators, using the same risk-scoring pipeline as URL analysis. Sample test files (`safe_email.eml`, `suspicious_email.eml`) are included in the repo for reference.

---

## 🧠 How Risk Scoring Works

| Check                                            | Risk Points |
|---------------------------------------------------|-------------|
| URL length > 75 chars                              | +1          |
| IP address in URL                                  | +2          |
| Suspicious keywords (login, verify, bank, etc.)    | +1          |
| No HTTPS                                           | +1          |
| Excessive hyphens                                  | +1          |
| Special characters (@ symbol, too many dots)       | +1 to +2    |
| Domain age < 30 days                               | +3          |

### Verdict

| Score       | Result                          |
|-------------|----------------------------------|
| 5 and above | 🚨 HIGH RISK / PHISHING LIKELY   |
| 2 – 4       | ⚠️ SUSPICIOUS – PROCEED WITH CAUTION |
| Below 2     | ✅ LIKELY SAFE                   |

---

## 🛠️ Installation & Setup

1. **Clone the repository**

git clone https://github.com/ishikajaiswal657/cyber-forensic-url-analyzer.git
cd cyber-forensic-url-analyzer


2. **Install dependencies**

pip install -r requirements.txt


3. **Run the web app**

python app.py


## 📦 Dependencies

- `Flask` – Web app framework
- `tldextract` – Domain extraction
- `python-whois` – WHOIS lookup
- `requests` – IP geolocation & VirusTotal API calls
- `ssl`, `socket` – SSL certificate inspection

---

## 📁 Output

Investigation reports are saved as:
`Case_YYYYMMDD_HHMMSS.txt`

---

## ⚠️ Disclaimer

This tool is intended strictly for **lawful cyber forensic investigations** by authorized personnel. Misuse of this tool for illegal activities is strictly prohibited.

---

## 👨‍💻 Author

**Ishika Jaiswal**
Cyber Security | Digital Forensics
[LinkedIn](https://linkedin.com/in/jaiswalishika) | [GitHub](https://github.com/ishikajaiswal657)


