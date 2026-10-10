
from __future__ import annotations

from typing import Any


class EvidenceFusion:
    """
    Combines rule-based, AI, and URL evidence.

    Decision policy:
    - Valid AI verdict True: always HIGH RISK, score at least 60.
    - Valid AI verdict False: retain the rule-based assessment.
    - AI unavailable or invalid: fall back to the rule-based assessment.
    - URL evidence is recorded but not added twice.
    - Preserve the existing combine() return interface.
    """

    AI_CONFIRMED_MIN_SCORE = 60

    def combine(
        self,
        rule_score: int,
        rule_level: str,
        rule_category: str,
        ai_analysis: dict[str, Any],
        url_analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        evidence: list[str] = []

        # ----------------------------------------------------
        # 1. Validate the rule-based baseline
        # ----------------------------------------------------
        try:
            baseline = max(0, min(100, int(rule_score)))
        except (TypeError, ValueError, OverflowError):
            baseline = 0
            evidence.append(
                "Invalid rule score; baseline defaulted to 0."
            )

        final_score = baseline

        evidence.append(f"Rule engine score: {baseline}/100")

        if isinstance(rule_level, str) and rule_level.strip():
            evidence.append(
                f"Rule engine level: {rule_level.strip()}"
            )

        # ----------------------------------------------------
        # 2. Record URL evidence without double-counting it
        # ----------------------------------------------------
        url_score = 0

        url_available = (
            isinstance(url_analysis, dict)
            and url_analysis.get("success") is True
        )

        if url_available:
            try:
                url_score = max(
                    0,
                    min(100, int(url_analysis.get("score", 0))),
                )
            except (TypeError, ValueError, OverflowError):
                evidence.append(
                    "URL analyzer returned an invalid score."
                )

            evidence.append(
                f"URL analyzer score: {url_score}/100 "
                "(recorded, not added again)."
            )

            signals = url_analysis.get("signals", [])

            if isinstance(signals, list):
                for signal in dict.fromkeys(signals):
                    if isinstance(signal, str):
                        evidence.append(
                            f"URL signal detected: {signal}"
                        )
        else:
            evidence.append(
                "URL evidence unavailable or unsuccessful."
            )

        # ----------------------------------------------------
        # 3. Normalize AI output
        # ----------------------------------------------------
        ai_data = (
            ai_analysis
            if isinstance(ai_analysis, dict)
            else {}
        )

        ai_result = ai_data.get("result")

        if isinstance(ai_result, dict):
            normalized_ai = ai_result
        elif "result" not in ai_data:
            normalized_ai = ai_data
        else:
            normalized_ai = {}

        # Explicit unavailable status invalidates the prediction.
        ai_available = ai_data.get("available") is True

        if "available" in ai_data and not ai_available:
            normalized_ai = {}

        prediction = normalized_ai.get("likely_scam")

        # Only a real boolean is an authoritative AI verdict.
        if not isinstance(prediction, bool):
            prediction = None

        ai_supported = prediction is True

        scam_type = normalized_ai.get("scam_type")

        if isinstance(scam_type, str) and scam_type.strip():
            scam_type = scam_type.strip()
        else:
            scam_type = None

        # ----------------------------------------------------
        # 4. Final decision: valid AI-positive verdict wins
        # ----------------------------------------------------
        if ai_available and prediction is True:
            final_score = max(
                baseline,
                self.AI_CONFIRMED_MIN_SCORE,
            )

            final_level = "HIGH RISK"

            evidence.append(
                "AUTHORITATIVE AI VERDICT: likely_scam=True. "
                "Final classification forced to HIGH RISK."
            )

        else:
            # AI-negative, unavailable, or invalid:
            # preserve the rule-based baseline and classification.
            final_score = baseline

            if baseline >= 60:
                final_level = "HIGH RISK"
            elif baseline >= 30:
                final_level = "SUSPICIOUS"
            else:
                final_level = "LOW RISK"

            if ai_available and prediction is False:
                evidence.append(
                    "AI verdict: likely_scam=False. "
                    "Retaining rule-based classification."
                )
            elif ai_available:
                evidence.append(
                    "AI verdict missing or invalid. "
                    "Falling back to rule-based classification."
                )
            else:
                evidence.append(
                    "AI unavailable. "
                    "Falling back to rule-based classification."
                )

        # ----------------------------------------------------
        # 5. Select category
        # ----------------------------------------------------
        final_category = (
            rule_category
            if isinstance(rule_category, str)
            and rule_category.strip()
            else "General Message"
        )

        generic_categories = {
            "General Message",
            "No Strong Rule Indicators",
        }

        if ai_supported and scam_type:
            if final_category in generic_categories:
                final_category = scam_type

            evidence.append(f"AI scam type: {scam_type}")

        # ----------------------------------------------------
        # 6. Preserve existing return structure
        # ----------------------------------------------------
        return {
            "score": final_score,
            "level": final_level,
            "category": final_category,
            "evidence": evidence,
            "ai_supported": ai_supported,
            "url_score": url_score,
        }


# ============================================================
# LOCAL SELF-TESTS
# ============================================================

if __name__ == "__main__":
    fusion = EvidenceFusion()

    tests = [
        {
            "name": "AI true overrides zero score",
            "score": 0,
            "ai": {
                "available": True,
                "result": {"likely_scam": True},
            },
            "expected_score": 60,
            "expected_level": "HIGH RISK",
        },
        {
            "name": "AI true preserves higher score",
            "score": 85,
            "ai": {
                "available": True,
                "result": {"likely_scam": True},
            },
            "expected_score": 85,
            "expected_level": "HIGH RISK",
        },
        {
            "name": "AI false preserves low rule score",
            "score": 20,
            "ai": {
                "available": True,
                "result": {"likely_scam": False},
            },
            "expected_score": 20,
            "expected_level": "LOW RISK",
        },
        {
            "name": "AI false preserves suspicious rules",
            "score": 40,
            "ai": {
                "available": True,
                "result": {"likely_scam": False},
            },
            "expected_score": 40,
            "expected_level": "SUSPICIOUS",
        },
        {
            "name": "AI unavailable uses rule score",
            "score": 20,
            "ai": {
                "available": False,
                "status": "error",
            },
            "expected_score": 20,
            "expected_level": "LOW RISK",
        },
        {
            "name": "Invalid AI verdict uses rule score",
            "score": 35,
            "ai": {
                "available": True,
                "result": {"likely_scam": "true"},
            },
            "expected_score": 35,
            "expected_level": "SUSPICIOUS",
        },
    ]

    for test in tests:
        result = fusion.combine(
            rule_score=test["score"],
            rule_level="",
            rule_category="General Message",
            ai_analysis=test["ai"],
        )

        passed = (
            result["score"] == test["expected_score"]
            and result["level"] == test["expected_level"]
        )

        print(
            f"[{'PASS' if passed else 'FAIL'}] "
            f"{test['name']} | "
            f"Score={result['score']} | "
            f"Level={result['level']}"
        )

        if not passed:
            raise AssertionError(
                f"{test['name']}: unexpected fusion result: {result}"
            )

    print("\nAll fusion self-tests passed.")
