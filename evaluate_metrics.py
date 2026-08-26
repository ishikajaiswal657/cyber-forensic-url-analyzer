import csv
import os
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from phishing_analyzer import analyze_url

TEST_SET_PATH = os.path.join(os.path.dirname(__file__), "test_set.csv")

# Some WHOIS servers hang indefinitely instead of timing out on their own.
# We cap every single URL scan at this many seconds so one slow/unresponsive
# lookup can never freeze the whole test run.
PER_URL_TIMEOUT_SECONDS = 20


def analyze_url_with_timeout(url, timeout=PER_URL_TIMEOUT_SECONDS):
    """
    Runs analyze_url(url) but gives up after `timeout` seconds instead of
    hanging forever. A fresh single-use executor is created per call (not
    reused) so that if one hung lookup never returns, it doesn't block or
    queue up behind future calls — we just abandon it and move on.
    """
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(analyze_url, url, verbose=False)
    try:
        result = future.result(timeout=timeout)
        executor.shutdown(wait=False)
        return result
    except FutureTimeoutError:
        executor.shutdown(wait=False)
        raise TimeoutError(f"Timed out after {timeout}s (likely a slow/unresponsive WHOIS server)")


def load_test_set(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row["url"].strip()
            label = row["label"].strip().lower()
            if url and label in ("phishing", "safe"):
                rows.append((url, label))
    return rows


def confusion_counts(results, flagged_verdicts):
    """
    results: list of (true_label, verdict) tuples
    flagged_verdicts: set of verdict strings counted as "predicted phishing"
    Returns tp, fp, tn, fn
    """
    tp = fp = tn = fn = 0
    for true_label, verdict in results:
        predicted_phishing = verdict in flagged_verdicts
        actually_phishing = true_label == "phishing"
        if predicted_phishing and actually_phishing:
            tp += 1
        elif predicted_phishing and not actually_phishing:
            fp += 1
        elif not predicted_phishing and not actually_phishing:
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn


def print_metrics(name, tp, fp, tn, fn):
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) and precision == precision and recall == recall
          else float("nan"))
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")

    print(f"\n--- {name} threshold ---")
    print(f"Confusion matrix (n={total}):")
    print(f"  True Positive (correctly flagged phishing):  {tp}")
    print(f"  False Positive (safe URL wrongly flagged):   {fp}")
    print(f"  True Negative (correctly allowed safe URL):  {tn}")
    print(f"  False Negative (missed phishing):            {fn}")
    print(f"Precision: {precision:.2f}   (of URLs flagged, % that were actually phishing)")
    print(f"Recall:    {recall:.2f}   (of actual phishing, % that got flagged)")
    print(f"F1 score:  {f1:.2f}")
    print(f"False-positive rate: {fpr:.2f}   (of safe URLs, % wrongly flagged)")


def main():
    if not os.path.exists(TEST_SET_PATH):
        print(f"ERROR: {TEST_SET_PATH} not found. Create it first (see sample_test_set.csv).")
        sys.exit(1)

    test_set = load_test_set(TEST_SET_PATH)
    if not test_set:
        print("ERROR: test_set.csv has no valid rows. Each row needs url,label (label = phishing/safe).")
        sys.exit(1)

    print(f"Running analyze_url() on {len(test_set)} labeled URLs...\n")

    results = []
    for i, (url, label) in enumerate(test_set, 1):
        print(f"[{i}/{len(test_set)}] Scanning: {url} (true label: {label})")
        try:
            result = analyze_url_with_timeout(url)
            verdict = result["verdict"]
        except KeyboardInterrupt:
            print("   -> Interrupted signal received while scanning this URL "
                  "(this can happen due to terminal quirks, e.g. Windows "
                  "'QuickEdit Mode'). Skipping this URL and continuing.")
            continue
        except Exception as e:
            print(f"   -> ERROR scanning this URL, skipping: {e}")
            continue
        print(f"   -> verdict: {verdict} (score: {result['score']})")
        results.append((label, verdict))

    if not results:
        print("\nNo URLs scanned successfully. Nothing to report.")
        return

    strict_flagged = {"HIGH RISK / PHISHING LIKELY"}
    lenient_flagged = {"HIGH RISK / PHISHING LIKELY", "SUSPICIOUS"}

    print("\n" + "=" * 50)
    print("RESULTS")
    print("=" * 50)

    tp, fp, tn, fn = confusion_counts(results, strict_flagged)
    print_metrics("STRICT (HIGH RISK only)", tp, fp, tn, fn)

    tp, fp, tn, fn = confusion_counts(results, lenient_flagged)
    print_metrics("LENIENT (SUSPICIOUS + HIGH RISK)", tp, fp, tn, fn)


if __name__ == "__main__":
    main()
