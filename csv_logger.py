import csv
import os
import datetime

LOG_PATH = os.path.join(os.path.dirname(__file__), "scan_log.csv")

FIELDNAMES = ["timestamp", "type", "identifier", "domain", "score", "verdict", "true_label"]


def _ensure_header():
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()


def log_scan(scan_type: str, identifier: str, domain: str, score, verdict: str):
    """
    scan_type: "url" or "email"
    identifier: the URL string, or the email subject/sender for .eml scans
    domain: the domain that was analyzed
    score: the numeric risk score
    verdict: the verdict string (e.g. "SUSPICIOUS")
    """
    _ensure_header()
    try:
        with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writerow({
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "type": scan_type,
                "identifier": identifier,
                "domain": domain or "",
                "score": score,
                "verdict": verdict,
                "true_label": "",  # fill this in manually later
            })
    except Exception as e:
        # Logging must never break the actual scan — fail silently but print for debugging
        print(f"[csv_logger] Failed to log scan: {e}")
