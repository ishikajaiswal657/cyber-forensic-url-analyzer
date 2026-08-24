import inspect
import json
import os
from datetime import datetime
from enum import Enum

from phishing_analyzer import analyze_url, analyze_email  # reuse the existing engine, untouched

AUDIT_LOG_PATH = "agent_audit_log.jsonl"

# Extra fintech-specific signal: domains/keywords that suggest the link
# is impersonating a payment flow (checkout, gateway, refund, etc.)
PAYMENT_IMPERSONATION_KEYWORDS = [
    "checkout", "razorpay", "refund", "payment", "invoice",
    "billing-update", "wallet", "upi", "pay-now"
]


def _call_flexible(func, *args, **kwargs):
    """
    Calls func with only the kwargs it actually accepts, so this file
    doesn't break if main.py's analyze_url/analyze_email signature
    doesn't include e.g. a `verbose` parameter. Falls back to calling
    with no kwargs at all if inspection fails for any reason.
    """
    try:
        accepted = set(inspect.signature(func).parameters)
        safe_kwargs = {k: v for k, v in kwargs.items() if k in accepted}
        return func(*args, **safe_kwargs)
    except (TypeError, ValueError):
        return func(*args)


class Decision(str, Enum):
    ALLOW = "ALLOW"
    FLAG_FOR_REVIEW = "FLAG_FOR_REVIEW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"  # agent isn't confident enough to decide alone


class RiskAgent:
    """
    Agentic wrapper around the existing scanner.

    "Agentic" here means the class does more than classify once — it:
      1. Perceives  -> runs the existing heuristic + VirusTotal scan
      2. Reasons     -> adds fintech-specific context (payment impersonation)
      3. Decides     -> picks an action, not just a score
      4. Explains    -> produces a plain-language reason for the decision
      5. Remembers   -> writes every decision to an audit trail (JSONL),
                        so repeat offenders and past context are visible
      6. Escalates   -> when signals conflict, it asks for a second,
                        deeper check instead of guessing
    """

    def __init__(self, log_path: str = AUDIT_LOG_PATH):
        self.log_path = log_path

    # ---------- step 2: fintech-specific reasoning on top of the base scan ----------
    def _payment_impersonation_bonus(self, url: str) -> tuple[int, list[str]]:
        notes = []
        hits = [k for k in PAYMENT_IMPERSONATION_KEYWORDS if k in url.lower()]
        bonus = 0
        if hits:
            bonus += 2
            notes.append(f"Payment-flow impersonation keywords found: {hits}")
        return bonus, notes

    # ---------- step 3 + 4: decide + explain ----------
    def _decide(self, score: int, verdict: str, context_notes: list[str]) -> tuple[Decision, str]:
        if verdict == "HIGH RISK / PHISHING LIKELY" and score >= 8:
            return Decision.BLOCK, (
                f"Score {score} is well past the high-risk threshold, and "
                f"multiple independent signals agree — safe to auto-block "
                f"without a human in the loop."
            )
        if verdict == "HIGH RISK / PHISHING LIKELY":
            return Decision.FLAG_FOR_REVIEW, (
                f"Score {score} clears the high-risk bar, but not by enough "
                f"margin to auto-block a live payment link — a false positive "
                f"here blocks a real transaction, so a human reviews it."
            )
        if verdict == "SUSPICIOUS" and context_notes:
            return Decision.ESCALATE, (
                "Base score is only 'suspicious', but fintech-specific context "
                "(payment-flow impersonation) was found — escalating for a "
                "deeper check rather than deciding on heuristics alone."
            )
        if verdict == "SUSPICIOUS":
            return Decision.FLAG_FOR_REVIEW, f"Score {score} is borderline — routed to manual review."
        return Decision.ALLOW, f"Score {score} — no meaningful risk signals found."

    # ---------- step 5: memory ----------
    def _log_decision(self, record: dict) -> None:
        record["timestamp"] = datetime.utcnow().isoformat() + "Z"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def _repeat_offender_check(self, domain: str) -> int:
        """Looks at past decisions for this domain — repeat flags raise risk."""
        if not os.path.exists(self.log_path):
            return 0
        count = 0
        with open(self.log_path, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("domain") == domain and rec.get("decision") != "ALLOW":
                    count += 1
        return count

    # ---------- recompute verdict after agent-level score adjustments ----------
    @staticmethod
    def _verdict_for_score(score: int) -> str:
        # Same thresholds main.py uses for analyze_url, applied to the
        # AGENT's adjusted score (base + fintech context + repeat-offender),
        # not just the base heuristic score.
        if score >= 5:
            return "HIGH RISK / PHISHING LIKELY"
        elif score >= 2:
            return "SUSPICIOUS"
        return "LIKELY SAFE"

    # ---------- public entry point ----------
    def assess_url(self, url: str) -> dict:
        base = _call_flexible(analyze_url, url, verbose=False)
        bonus, context_notes = self._payment_impersonation_bonus(url)
        score = base["score"] + bonus

        repeat_flags = self._repeat_offender_check(base["domain"])
        if repeat_flags:
            score += min(repeat_flags, 3)
            context_notes.append(f"Domain flagged {repeat_flags}x previously in audit log")

        # BUG FIX: verdict must reflect the agent's adjusted score, not the
        # base heuristic score. Previously this used base["verdict"] directly,
        # which meant a low-heuristic-score URL that impersonated a payment
        # flow could score high enough to matter but still fall through to
        # ALLOW, because its *base* verdict was "LIKELY SAFE" before bonuses.
        verdict = self._verdict_for_score(score)
        decision, explanation = self._decide(score, verdict, context_notes)

        record = {
            "url": url,
            "domain": base["domain"],
            "base_score": base["score"],
            "agent_score": score,
            "verdict": verdict,
            "decision": decision.value,
            "explanation": explanation,
            "context_notes": context_notes,
        }
        self._log_decision(record)
        return record

    def assess_email(self, filepath: str) -> dict:
        base = _call_flexible(analyze_email, filepath, verbose=False)
        decision, explanation = self._decide(base["score"], base["verdict"], base["notes"])
        record = {
            "subject": base["subject"],
            "sender": base["sender"],
            "domain": base.get("from_domain"),
            "agent_score": base["score"],
            "verdict": base["verdict"],
            "decision": decision.value,
            "explanation": explanation,
            "context_notes": base["notes"],
        }
        self._log_decision(record)
        return record


def print_decision(record: dict) -> None:
    icon = {"ALLOW": "✅", "FLAG_FOR_REVIEW": "⚠️", "BLOCK": "🚫", "ESCALATE": "🔺"}
    print("=" * 50)
    print(f"{icon.get(record['decision'], '')} DECISION: {record['decision']}")
    print(f"Reason: {record['explanation']}")
    if record["context_notes"]:
        print("Context:")
        for note in record["context_notes"]:
            print(f"  - {note}")
    print("=" * 50)


if __name__ == "__main__":
    agent = RiskAgent()
    test_url = input("Enter a payment link / merchant URL to assess: ").strip()
    result = agent.assess_url(test_url)
    print_decision(result)
