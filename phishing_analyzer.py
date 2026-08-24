import re
import tldextract
import whois
from datetime import datetime
import socket
import requests
import ssl
import json
import os
import time
import argparse
import csv
from dotenv import load_dotenv

# --- NEW: email parsing imports (added for email-checking feature) ---
import email
from email import policy
from email.parser import BytesParser

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# Set default socket timeout (in seconds) to prevent third-party libraries (like python-whois)
# from hanging indefinitely when connection/firewall issues arise.
socket.setdefaulttimeout(3)

# --- NEW: constants for email analysis ---
DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar",
    ".ps1", ".msi", ".com", ".pif"
)

URGENCY_PHRASES = [
    "act now", "verify your account", "suspended", "immediately",
    "click here", "confirm your identity", "unusual activity",
    "limited time", "your account will be locked", "urgent action required"
]

# --- HEURISTIC FUNCTIONS ---
def check_length(url):
    # Measure length without the query string. Phishing URLs are usually
    # long because of an obfuscated/padded PATH (trying to hide the real
    # destination) — legitimate marketing/tracking links are long because
    # of utm_* parameters and tokens in the QUERY STRING, which is normal
    # and not itself suspicious.
    base_url = url.split("?", 1)[0]
    return 1 if len(base_url) > 75 else 0

def has_ip(url):
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    return 2 if re.search(ip_pattern, url) else 0

def suspicious_keywords(url):
    keywords = ["login", "verify", "bank", "update", "secure", "account", "kyc", "free", "gift"]
    for word in keywords:
        if word in url.lower():
            return 1
    return 0

def https_check(url):
    return 0 if url.startswith("https://") else 1

def hyphen_check(url):
    # Only count hyphens in the actual domain name, not the full URL.
    # Fake phishing domains often stack hyphens to mimic real brands
    # (e.g. "paypal-secure-login-verify.com"), but a hyphen count on the
    # WHOLE url also flags any legitimate link containing a UUID or token
    # in its path/query string (UUIDs always contain 4 hyphens by design —
    # e.g. Railway, Stripe, AWS, Notion links all do this).
    ext = tldextract.extract(url)
    domain_only = ext.domain  # just "paypal-secure-login-verify", not the path/query
    return 1 if domain_only.count("-") > 3 else 0

def extract_domain(url):
    ext = tldextract.extract(url)
    # Joining domain and suffix for accurate WHOIS (e.g., google.com)
    return f"{ext.domain}.{ext.suffix}"

def check_special_chars(url):
    risk = 0
    if "@" in url: risk += 2
    if url.count(".") > 4: risk += 1
    return risk

# --- NEW: helper reused by email header checks ---
def _domain_of(address):
    """Extract domain from an address like 'Name <user@domain.com>'."""
    if not address:
        return None
    match = re.search(r'@([\w\.-]+)', address)
    if not match:
        return None
    ext = tldextract.extract(match.group(1))
    return f"{ext.domain}.{ext.suffix}"

# --- FORENSIC FUNCTIONS ---
def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return creation_date, age_days
    except Exception:
        return None, None
    return None, None

def _safe_get_json(url, headers=None, hard_timeout=6):
    """Runs requests.get in a background thread and hard-kills it after
    hard_timeout seconds no matter what the underlying socket is doing."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(requests.get, url, headers=headers, timeout=5)
        try:
            return future.result(timeout=hard_timeout).json()
        except Exception:
            return None

def get_ip_geo(domain):
    try:
        ip_addr = socket.gethostbyname(domain)
    except Exception:
        return {
            "ip": "Offline (No DNS record)",
            "city": "N/A",
            "country": "Offline",
            "isp": "N/A"
        }

    # Try ip-api.com (free, reliable, no Cloudflare blocks)
    response = _safe_get_json(f"http://ip-api.com/json/{ip_addr}")
    if response and response.get("status") == "success":
        return {
            "ip": ip_addr,
            "city": response.get("city") or "Unknown",
            "country": response.get("country") or "Unknown",
            "isp": response.get("isp") or "Unknown"
        }

    # Fallback to ipapi.co
    response = _safe_get_json(f"https://ipapi.co/{ip_addr}/json/", headers={'User-Agent': 'Mozilla/5.0'})
    if response and "error" not in response:
        return {
            "ip": ip_addr,
            "city": response.get("city") or "Unknown",
            "country": response.get("country_name") or "Unknown",
            "isp": response.get("org") or "Unknown"
        }

    # Fallback to returning resolved IP if Geo-IP APIs fail
    return {
        "ip": ip_addr,
        "city": "Unknown",
        "country": "Unknown",
        "isp": "Unknown"
    }

def check_ssl_details(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                return issuer.get('commonName')
    except Exception:
        return "No SSL/Expired/Self-Signed"

def check_virustotal(url):
    """
    Submits the URL to VirusTotal and returns security scan results.
    Returns a dict containing 'status' and results, or None if the check failed.
    """
    if not VT_API_KEY:
        return None  # keep None so frontend knows it's unconfigured

    headers = {"x-apikey": VT_API_KEY}

    import base64
    try:
        # Encode URL to base64 ID without padding as required by VT API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Step 1: Try to retrieve existing analysis report (fastest, no polling)
        url_report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        report_resp = requests.get(url_report_url, headers=headers, timeout=(5, 10))
        
        if report_resp.status_code == 200:
            stats = report_resp.json()["data"]["attributes"].get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
        
        # Step 2: If report is not found (404), submit for a new analysis
        elif report_resp.status_code == 404:
            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=(5, 10)
            )
            submit_resp.raise_for_status()
            analysis_id = submit_resp.json()["data"]["id"]

            # Step 3: Poll analysis result
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for attempt in range(6):  # up to ~12 seconds of waiting
                result_resp = requests.get(analysis_url, headers=headers, timeout=(5, 10))
                result_resp.raise_for_status()
                data = result_resp.json()["data"]["attributes"]
                status = data.get("status")
                if status == "completed":
                    stats = data.get("stats", {})
                    return {
                        "status": "success",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                    }
                elif status == "failed":
                    return {
                        "status": "failed",
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 0
                    }
                time.sleep(2)

            return {
                "status": "error",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            }
            
        else:
            return None

    except requests.exceptions.RequestException:
        # covers timeouts, rate limits, no internet, bad key, etc.
        return None

# --- CORE ANALYSIS (used by both single-URL and bulk modes) ---
def analyze_url(url, verbose=True):
    """
    Runs the full analysis pipeline on one URL and returns a result dict.
    Set verbose=False to suppress the "Fetching OSINT Data..." print,
    which keeps bulk-mode output clean when scanning many URLs.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    domain = extract_domain(url)

    if verbose:
        print(f"\n[🔍] Fetching OSINT Data for: {domain}...")

    created_date, age_days = get_domain_age(domain)
    geo = get_ip_geo(domain)
    ssl_issuer = check_ssl_details(domain)
    vt_result = check_virustotal(url)

    # Calculate Risk Score
    score = 0
    score += check_length(url)
    score += has_ip(url)
    score += suspicious_keywords(url)
    score += https_check(url)
    score += hyphen_check(url)
    score += check_special_chars(url)

    if isinstance(age_days, int) and age_days < 30:
        score += 3

    if vt_result and vt_result.get("status") == "success":
        if vt_result.get("malicious", 0) >= 5:
            score += 5
        elif vt_result.get("malicious", 0) >= 3 or vt_result.get("suspicious", 0) >= 5:
            score += 2

    if score >= 5:
        verdict = "HIGH RISK / PHISHING LIKELY"
    elif score >= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"

    return {
        "url": url,
        "domain": domain,
        "created_date": created_date,
        "age_days": age_days,
        "ssl_issuer": ssl_issuer,
        "geo": geo,
        "vt_result": vt_result,
        "score": score,
        "verdict": verdict,
    }


def format_report(result):
    """Builds the human-readable report text from an analyze_url() result."""
    report = f"""
------------------------------
 TECHNICAL ANALYSIS REPORT
------------------------------
URL:      {result['url']}
Domain:   {result['domain']}
Created:  {result['created_date'] if result['created_date'] else 'N/A'} ({result['age_days'] if result['age_days'] else 'Unknown'} days ago)
SSL:      {result['ssl_issuer']}
"""
    geo = result["geo"]
    if geo:
        report += f"Server:   {geo['ip']} ({geo['isp']})\nLocation: {geo['city']}, {geo['country']} 📍\n"

    vt_result = result["vt_result"]
    if vt_result and vt_result.get("status") == "success":
        total_vendors = vt_result['malicious'] + vt_result['suspicious'] + vt_result['harmless'] + vt_result['undetected']
        report += (f"VirusTotal: {vt_result['malicious']} malicious / "
                   f"{vt_result['suspicious']} suspicious / "
                   f"{vt_result['harmless']} clean (out of {total_vendors} vendors)\n")
    elif vt_result and vt_result.get("status") == "failed":
        report += "VirusTotal: Scan failed (domain offline or unreachable)\n"
    else:
        report += "VirusTotal: Unavailable (no API key or rate limit)\n"

    report += f"{'-'*30}\nFINAL RISK SCORE: {result['score']}\n"

    icon = {"HIGH RISK / PHISHING LIKELY": "🚨", "SUSPICIOUS": "⚠️", "LIKELY SAFE": "✅"}[result["verdict"]]
    report += f"VERDICT: {icon} {result['verdict']}\n{'-'*30}"
    return report


# =================================================================
# NEW SECTION: EMAIL ANALYSIS
# Everything below this line is new — added to check whether an
# email (.eml file) is legitimate or phishing, reusing analyze_url()
# for any links found inside the email body.
# =================================================================

def check_header_spoofing(msg):
    """
    Compares From / Reply-To / Return-Path domains.
    A mismatch is a strong phishing signal (attacker controls Reply-To
    or Return-Path but spoofs a trusted From address).
    """
    from_domain = _domain_of(msg.get("From"))
    reply_to_domain = _domain_of(msg.get("Reply-To"))
    return_path_domain = _domain_of(msg.get("Return-Path"))

    mismatch_score = 0
    notes = []

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        mismatch_score += 3
        notes.append(f"Reply-To domain ({reply_to_domain}) != From domain ({from_domain})")

    if return_path_domain and from_domain and return_path_domain != from_domain:
        mismatch_score += 2
        notes.append(f"Return-Path domain ({return_path_domain}) != From domain ({from_domain})")

    return mismatch_score, notes, from_domain


def check_auth_results(msg):
    """
    Parses the Authentication-Results header (set by the receiving mail
    server) for SPF / DKIM / DMARC pass-fail status. Not every email
    will have this header, so 'missing' is treated as neutral, not bad.
    """
    header = msg.get("Authentication-Results", "")
    results = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf'{mechanism}=(\w+)', header, re.IGNORECASE)
        results[mechanism] = match.group(1).lower() if match else "none"

    score = 0
    if results["spf"] == "fail":
        score += 2
    if results["dkim"] == "fail":
        score += 2
    if results["dmarc"] == "fail":
        score += 3

    return score, results


def extract_body_text(msg):
    """Pulls plain text body; falls back to stripping tags from HTML part."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_content()
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                html = part.get_content()
                return re.sub(r'<[^>]+>', ' ', html)
    else:
        return msg.get_content()
    return ""


def check_body_keywords(body_text):
    text = body_text.lower()
    hits = [phrase for phrase in URGENCY_PHRASES if phrase in text]
    return len(hits), hits


def extract_urls_from_body(body_text):
    url_pattern = r'https?://[^\s"\'<>]+'
    return list(set(re.findall(url_pattern, body_text)))


def check_attachments(msg):
    risky = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename and filename.lower().endswith(DANGEROUS_EXTENSIONS):
            risky.append(filename)
    return len(risky) * 3, risky


def analyze_email(filepath, scan_urls=True, verbose=True):
    """
    Runs the full email analysis pipeline and returns a result dict,
    matching the style of analyze_url()'s return value.
    """
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg.get("Subject", "(no subject)")
    sender = msg.get("From", "(unknown sender)")

    if verbose:
        print(f"\n[📧] Analyzing email: {subject}  |  From: {sender}")

    score = 0
    notes = []

    header_score, header_notes, from_domain = check_header_spoofing(msg)
    score += header_score
    notes.extend(header_notes)

    auth_score, auth_results = check_auth_results(msg)
    score += auth_score
    if auth_score:
        notes.append(f"Auth failures detected: {auth_results}")

    body_text = extract_body_text(msg)
    keyword_count, keyword_hits = check_body_keywords(body_text)
    score += min(keyword_count, 4)  # cap so one email can't blow up the scale
    if keyword_hits:
        notes.append(f"Urgency/phishing phrases found: {keyword_hits}")

    attach_score, risky_attachments = check_attachments(msg)
    score += attach_score
    if risky_attachments:
        notes.append(f"Risky attachments: {risky_attachments}")

    # Reuses your existing analyze_url() for every link found in the body.
    # Capped at 5 links so a link-heavy email (common in marketing/phishing
    # mail) can't cause the request to time out on slower hosting.
    url_results = []
    if scan_urls:
        found_urls = extract_urls_from_body(body_text)
        skipped_count = max(0, len(found_urls) - 5)
        for url in found_urls[:5]:
            result = analyze_url(url, verbose=False)
            url_results.append(result)
            if result["verdict"] == "HIGH RISK / PHISHING LIKELY":
                score += 4
            elif result["verdict"] == "SUSPICIOUS":
                score += 1
        if skipped_count:
            notes.append(f"{skipped_count} additional link(s) in this email were not scanned (limit: 5 per email)")

    if score >= 8:
        verdict = "HIGH RISK / PHISHING LIKELY"
    elif score >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY LEGITIMATE"

    return {
        "subject": subject,
        "sender": sender,
        "from_domain": from_domain,
        "auth_results": auth_results,
        "notes": notes,
        "url_results": url_results,
        "score": score,
        "verdict": verdict,
    }


def format_email_report(result):
    """Builds the human-readable report text from an analyze_email() result."""
    icon = {
        "HIGH RISK / PHISHING LIKELY": "🚨",
        "SUSPICIOUS": "⚠️",
        "LIKELY LEGITIMATE": "✅"
    }[result["verdict"]]

    report = f"""
------------------------------
 EMAIL FORENSIC ANALYSIS REPORT
------------------------------
Subject:  {result['subject']}
From:     {result['sender']}
SPF/DKIM/DMARC: {result['auth_results']}
"""
    if result["notes"]:
        report += "\nFlags:\n" + "\n".join(f"  - {n}" for n in result["notes"]) + "\n"

    if result["url_results"]:
        report += f"\nEmbedded URLs scanned: {len(result['url_results'])}\n"
        for r in result["url_results"]:
            report += f"  - {r['url']} -> {r['verdict']} (score {r['score']})\n"

    report += f"\n{'-'*30}\nFINAL RISK SCORE: {result['score']}\n"
    report += f"VERDICT: {icon} {result['verdict']}\n{'-'*30}"
    return report

# =================================================================
# END OF NEW EMAIL SECTION
# =================================================================


# --- SINGLE URL MODE (original interactive behaviour) ---
def run_investigation():
    print("==============================================")
    print("🛡️  CYBER CELL FORENSIC URL ANALYZER")
    print("==============================================\n")

    url = input("Enter URL to investigate: ").strip()
    result = analyze_url(url)
    report = format_report(result)
    print(report)

    save = input("\nSave this report for case file? (y/n): ").lower()
    if save == 'y':
        filename = f"Case_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report saved as {filename}")


# --- BULK MODE ---
def run_bulk_scan(filepath):
    """
    Reads URLs from a .txt (one per line) or .csv (one URL per row, first
    column) file, scans each one, prints a short progress line per URL, and
    saves all results into a single CSV report.
    """
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        return

    # --- read URLs from the file ---
    urls = []
    if filepath.lower().endswith(".csv"):
        with open(filepath, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if row and row[0].strip():
                    urls.append(row[0].strip())
    else:  # treat anything else as plain text, one URL per line
        with open(filepath, encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]

    if not urls:
        print("❌ No URLs found in file.")
        return

    print("==============================================")
    print(f"🛡️  BULK SCAN — {len(urls)} URLs from {filepath}")
    print("==============================================\n")

    results = []
    for i, url in enumerate(urls, start=1):
        print(f"[{i}/{len(urls)}] Scanning: {url}")
        result = analyze_url(url, verbose=False)
        results.append(result)
        print(f"    -> Score: {result['score']}  |  Verdict: {result['verdict']}\n")

    # --- save combined CSV report ---
    out_filename = f"Bulk_Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(out_filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "domain", "score", "verdict", "vt_malicious", "vt_suspicious", "vt_harmless"])
        for r in results:
            vt = r["vt_result"] or {}
            writer.writerow([
                r["url"], r["domain"], r["score"], r["verdict"],
                vt.get("malicious", ""), vt.get("suspicious", ""), vt.get("harmless", "")
            ])

    print("==============================================")
    print(f"✅ Bulk scan complete. Results saved to: {out_filename}")
    high_risk = sum(1 for r in results if r["verdict"] == "HIGH RISK / PHISHING LIKELY")
    print(f"   {high_risk} of {len(results)} URLs flagged HIGH RISK")
    print("==============================================")


# --- NEW: EMAIL MODE (single .eml file) ---
def run_email_scan(filepath):
    """Analyzes a single .eml file and prints (and optionally saves) the report."""
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        return

    result = analyze_email(filepath)
    report = format_email_report(result)
    print(report)

    save = input("\nSave this report for case file? (y/n): ").lower()
    if save == 'y':
        filename = f"Email_Case_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report saved as {filename}")


# --- NEW: interactive menu so we only run the check the user actually wants ---
def run_interactive_menu():
    print("==============================================")
    print("🛡️  CYBER CELL FORENSIC ANALYZER")
    print("==============================================")
    print("What do you want to check?")
    print("  1. URL")
    print("  2. Email (.eml file)")

    choice = input("Enter choice (1/2): ").strip()

    if choice == "1":
        run_investigation()
    elif choice == "2":
        filepath = input("Enter path to .eml file: ").strip()
        run_email_scan(filepath)
    else:
        print("❌ Invalid choice. Please enter 1 or 2.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Cell Forensic URL & Email Analyzer")
    parser.add_argument("--file", help="Path to a .txt or .csv file of URLs to bulk scan")
    parser.add_argument("--eml", help="Path to a .eml email file to analyze")
    args = parser.parse_args()

    # If a flag was passed explicitly, honor it directly (no need to ask).
    if args.file:
        run_bulk_scan(args.file)
    elif args.eml:
        run_email_scan(args.eml)
    else:
        # No flags given -> ask the user which single check they want,
        # instead of running both URL and email logic.
        run_interactive_menu()