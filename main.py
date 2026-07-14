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

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# --- HEURISTIC FUNCTIONS ---
def check_length(url):
    return 1 if len(url) > 75 else 0

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
    return 1 if url.count("-") > 3 else 0

def extract_domain(url):
    ext = tldextract.extract(url)
    # Joining domain and suffix for accurate WHOIS (e.g., google.com)
    return f"{ext.domain}.{ext.suffix}"

def check_special_chars(url):
    risk = 0
    if "@" in url: risk += 2
    if url.count(".") > 4: risk += 1
    return risk

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

def get_ip_geo(domain):
    try:
        ip_addr = socket.gethostbyname(domain)
        response = requests.get(f"https://ipapi.co/{ip_addr}/json/", timeout=5).json()
        return {
            "ip": ip_addr,
            "city": response.get("city"),
            "country": response.get("country_name"),
            "isp": response.get("org")
        }
    except Exception:
        return None

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
    Submits the URL to VirusTotal and returns how many security vendors
    flagged it as malicious or suspicious.
    Returns a dict, or None if the check failed (no key, no internet, rate limit, etc).
    """
    if not VT_API_KEY:
        return None  # no key configured, skip silently

    headers = {"x-apikey": VT_API_KEY}

    try:
        # Step 1: submit the URL for analysis
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        submit_resp.raise_for_status()
        analysis_id = submit_resp.json()["data"]["id"]

        # Step 2: fetch the analysis result — poll until the scan is actually done.
        # VirusTotal queues the scan first, so an immediate fetch often returns
        # empty stats. We check the "status" field and retry a few times.
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        stats = {}
        for attempt in range(6):  # up to ~12 seconds of waiting
            result_resp = requests.get(analysis_url, headers=headers, timeout=10)
            result_resp.raise_for_status()
            data = result_resp.json()["data"]["attributes"]
            if data.get("status") == "completed":
                stats = data.get("stats", {})
                break
            time.sleep(2)  # scan still running — wait before checking again

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

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

    if vt_result:
        if vt_result["malicious"] >= 5:
            score += 5
        elif vt_result["malicious"] >= 1 or vt_result["suspicious"] >= 3:
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
    if vt_result:
        report += (f"VirusTotal: {vt_result['malicious']} malicious / "
                   f"{vt_result['suspicious']} suspicious / "
                   f"{vt_result['harmless']} clean (out of {sum(vt_result.values())} vendors)\n")
    else:
        report += "VirusTotal: Unavailable (no API key or rate limit)\n"

    report += f"{'-'*30}\nFINAL RISK SCORE: {result['score']}\n"

    icon = {"HIGH RISK / PHISHING LIKELY": "🚨", "SUSPICIOUS": "⚠️", "LIKELY SAFE": "✅"}[result["verdict"]]
    report += f"VERDICT: {icon} {result['verdict']}\n{'-'*30}"
    return report


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


# --- BULK MODE (new) ---
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Cell Forensic URL Analyzer")
    parser.add_argument("--file", help="Path to a .txt or .csv file of URLs to bulk scan")
    args = parser.parse_args()

    if args.file:
        run_bulk_scan(args.file)
    else:
        run_investigation()
