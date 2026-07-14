import re
import tldextract
import whois
from datetime import datetime
import socket
import requests
import ssl
import json

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

# --- MAIN INVESTIGATION ---
def run_investigation():
    print("==============================================")
    print("🛡️  CYBER CELL FORENSIC URL ANALYZER")
    print("==============================================\n")
    
    url = input("Enter URL to investigate: ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url 
        
    domain = extract_domain(url)
    
    print(f"\n[🔍] Fetching OSINT Data for: {domain}...")
    created_date, age_days = get_domain_age(domain)
    geo = get_ip_geo(domain)
    ssl_issuer = check_ssl_details(domain)
    
    # Calculate Risk Score
    score = 0
    score += check_length(url)
    score += has_ip(url)
    score += suspicious_keywords(url)
    score += https_check(url)
    score += hyphen_check(url)
    score += check_special_chars(url)
    
    # Fixed Logic: check if age_days is an integer before comparing
    if isinstance(age_days, int) and age_days < 30:
        score += 3  

    # --- REPORT GENERATION ---
    report = f"""
------------------------------
 TECHNICAL ANALYSIS REPORT
------------------------------
URL:      {url}
Domain:   {domain}
Created:  {created_date if created_date else 'N/A'} ({age_days if age_days else 'Unknown'} days ago)
SSL:      {ssl_issuer}
"""
    if geo:
        report += f"Server:   {geo['ip']} ({geo['isp']})\nLocation: {geo['city']}, {geo['country']} 📍\n"
    
    report += f"{'-'*30}\nFINAL RISK SCORE: {score}\n"
    
    if score >= 5:
        verdict = "VERDICT: 🚨 HIGH RISK / PHISHING LIKELY"
    elif score >= 2:
        verdict = "VERDICT: ⚠️ SUSPICIOUS - PROCEED WITH CAUTION"
    else:
        verdict = "VERDICT: ✅ LIKELY SAFE"
    
    print(report + verdict + f"\n{'-'*30}")

    # --- FORENSIC EXPORT ---
    save = input("\nSave this report for case file? (y/n): ").lower()
    if save == 'y':
        filename = f"Case_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report + verdict)
        print(f"Report saved as {filename}")

if __name__ == "__main__":
    run_investigation()
