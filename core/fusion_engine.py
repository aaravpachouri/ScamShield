from __future__ import annotations

from typing import Any


class EvidenceFusion:
    """Combines rule-based, AI, and URL evidence without double-counting.

    Policy:
    - A valid AI-positive verdict forces HIGH RISK with a score of at least 60.
    - A verified malicious URL reputation match forces HIGH RISK with a score
      of at least 98, even if the message text itself looks ordinary.
    - AI-negative, unavailable, or invalid results retain the rule baseline.
    - URL scores are recorded, not added a second time.
    """

    AI_CONFIRMED_MIN_SCORE = 60
    VERIFIED_URL_MIN_SCORE = 98

    def combine(
        self,
        rule_score: int,
        rule_level: str,
        rule_category: str,
        ai_analysis: dict[str, Any],
        url_analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        evidence: list[str] = []

        try:
            baseline = max(0, min(100, int(rule_score)))
        except (TypeError, ValueError, OverflowError):
            baseline = 0
            evidence.append("Invalid rule score; baseline defaulted to 0.")

        final_score = baseline
        evidence.append(f"Rule engine score: {baseline}/100")

        if isinstance(rule_level, str) and rule_level.strip():
            evidence.append(f"Rule engine level: {rule_level.strip()}")

        url_score = 0
        url_available = isinstance(url_analysis, dict) and url_analysis.get("success") is True
        reputation_status = "unknown"

        if url_available:
            try:
                url_score = max(0, min(100, int(url_analysis.get("score", 0))))
            except (TypeError, ValueError, OverflowError):
                evidence.append("URL analyzer returned an invalid score.")

            reputation_status = str(url_analysis.get("reputation_status", "unknown"))
            evidence.append(f"URL analyzer score: {url_score}/100 (recorded, not added again).")
            evidence.append(f"URL reputation status: {reputation_status}.")

            signals = url_analysis.get("signals", [])
            if isinstance(signals, list):
                for signal in dict.fromkeys(signals):
                    if isinstance(signal, str):
                        evidence.append(f"URL signal detected: {signal}")
        else:
            evidence.append("URL evidence unavailable or unsuccessful.")
            if isinstance(url_analysis, dict):
                reputation_status = str(url_analysis.get("reputation_status", "unknown"))
                evidence.append(f"URL reputation status: {reputation_status}.")

        ai_data = ai_analysis if isinstance(ai_analysis, dict) else {}
        ai_result = ai_data.get("result")
        if isinstance(ai_result, dict):
            normalized_ai = ai_result
        elif "result" not in ai_data:
            normalized_ai = ai_data
        else:
            normalized_ai = {}

        ai_available = ai_data.get("available") is True
        if "available" in ai_data and not ai_available:
            normalized_ai = {}

        prediction = normalized_ai.get("likely_scam")
        if not isinstance(prediction, bool):
            prediction = None

        ai_supported = prediction is True
        scam_type = normalized_ai.get("scam_type")
        if isinstance(scam_type, str) and scam_type.strip():
            scam_type = scam_type.strip()
        else:
            scam_type = None

        if ai_available and prediction is True:
            final_score = max(baseline, self.AI_CONFIRMED_MIN_SCORE)
            final_level = "HIGH RISK"
            evidence.append(
                "AI verdict: likely_scam=True. Final classification set to HIGH RISK."
            )
        else:
            final_score = baseline
            if baseline >= 60:
                final_level = "HIGH RISK"
            elif baseline >= 30:
                final_level = "SUSPICIOUS"
            else:
                final_level = "LOW RISK"

            if ai_available and prediction is False:
                evidence.append("AI verdict: likely_scam=False. Retaining rule-based classification.")
            elif ai_available:
                evidence.append("AI verdict missing or invalid. Falling back to rule-based classification.")
            else:
                evidence.append("AI unavailable. Falling back to rule-based classification.")

        final_category = (
            rule_category
            if isinstance(rule_category, str) and rule_category.strip()
            else "General Message"
        )
        generic_categories = {"General Message", "No Strong Rule Indicators"}
        if ai_supported and scam_type:
            if final_category in generic_categories:
                final_category = scam_type
            evidence.append(f"AI scam type: {scam_type}")

        # A verified reputation hit is independent evidence; do not let a clean
        # message or negative AI answer erase it.
        if reputation_status == "confirmed_malicious":
            final_score = max(final_score, self.VERIFIED_URL_MIN_SCORE)
            final_level = "HIGH RISK"
            if final_category in generic_categories or final_category in {
                "Suspicious URL Indicators",
                "URL Present - Needs Verification",
                "URL Present",
                "Message Contains URL",
            }:
                final_category = "Confirmed Malicious URL"
            evidence.append(
                "VERIFIED URL THREAT: provider returned a verified phishing match; final score forced to at least 98/100."
            )

        return {
            "score": final_score,
            "level": final_level,
            "category": final_category,
            "evidence": evidence,
            "ai_supported": ai_supported,
            "url_score": url_score,
            "url_reputation_status": reputation_status,
        }


if __name__ == "__main__":
    fusion = EvidenceFusion()
    tests = [
        {
            "name": "AI true overrides zero score",
            "score": 0,
            "ai": {"available": True, "result": {"likely_scam": True}},
            "url": None,
            "expected_score": 60,
            "expected_level": "HIGH RISK",
        },
        {
            "name": "AI true preserves higher score",
            "score": 85,
            "ai": {"available": True, "result": {"likely_scam": True}},
            "url": None,
            "expected_score": 85,
            "expected_level": "HIGH RISK",
        },
        {
            "name": "AI false preserves low rule score",
            "score": 20,
            "ai": {"available": True, "result": {"likely_scam": False}},
            "url": None,
            "expected_score": 20,
            "expected_level": "LOW RISK",
        },
        {
            "name": "AI unavailable uses rule score",
            "score": 20,
            "ai": {"available": False, "status": "error"},
            "url": None,
            "expected_score": 20,
            "expected_level": "LOW RISK",
        },
        {
            "name": "Verified URL forces high risk despite clean message",
            "score": 0,
            "ai": {"available": True, "result": {"likely_scam": False}},
            "url": {"success": True, "score": 100, "reputation_status": "confirmed_malicious", "signals": ["confirmed_malicious_url"]},
            "expected_score": 98,
            "expected_level": "HIGH RISK",
        },
        {
            "name": "No known threat does not force a risk level",
            "score": 0,
            "ai": {"available": False},
            "url": {"success": True, "score": 0, "reputation_status": "no_known_threats", "signals": []},
            "expected_score": 0,
            "expected_level": "LOW RISK",
        },
    ]

    for test in tests:
        result = fusion.combine(
            rule_score=test["score"],
            rule_level="",
            rule_category="General Message",
            ai_analysis=test["ai"],
            url_analysis=test["url"],
        )
        passed = result["score"] == test["expected_score"] and result["level"] == test["expected_level"]
        print(f"[{'PASS' if passed else 'FAIL'}] {test['name']} | Score={result['score']} | Level={result['level']}")
        if not passed:
            raise AssertionError(f"{test['name']}: unexpected result: {result}")
    print("\nAll fusion self-tests passed.")
