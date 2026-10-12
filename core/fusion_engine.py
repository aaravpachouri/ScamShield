from __future__ import annotations

from typing import Any


class EvidenceFusion:
    """Conservative fusion of rule, AI, and URL evidence.

    The AI model is advisory, not a standalone authority. An AI-positive
    prediction cannot independently turn an otherwise low-risk message into
    HIGH RISK. High risk requires strong rule evidence plus AI corroboration,
    a rule-only high-risk score, or a confirmed malicious URL reputation hit.
    """

    RULE_HIGH_SCORE = 60
    AI_CORROBORATION_MIN_RULE_SCORE = 35
    AI_CORROBORATION_MIN_CONFIDENCE = 75
    AI_CONFIRMED_MIN_SCORE = 60
    VERIFIED_URL_MIN_SCORE = 98

    GENERIC_CATEGORIES = {
        "General Message",
        "No Strong Rule Indicators",
        "URL Present - Needs Verification",
        "URL Present",
        "Message Contains URL",
    }

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

        evidence.append(f"Rule engine score: {baseline}/100")
        if isinstance(rule_level, str) and rule_level.strip():
            evidence.append(f"Rule engine level: {rule_level.strip()}")

        url_score = 0
        reputation_status = "unknown"
        url_available = isinstance(url_analysis, dict) and url_analysis.get("success") is True
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
        raw_result = ai_data.get("result")
        if isinstance(raw_result, dict):
            normalized_ai = raw_result
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

        try:
            confidence = normalized_ai.get("confidence")
            confidence = int(confidence) if confidence is not None else None
            if confidence is not None:
                confidence = max(0, min(100, confidence))
        except (TypeError, ValueError, OverflowError):
            confidence = None

        scam_type = normalized_ai.get("scam_type")
        if not isinstance(scam_type, str) or not scam_type.strip():
            scam_type = None
        else:
            scam_type = scam_type.strip()

        ai_positive = ai_available and prediction is True
        ai_corroborated = bool(
            ai_positive
            and baseline >= self.AI_CORROBORATION_MIN_RULE_SCORE
            and confidence is not None
            and confidence >= self.AI_CORROBORATION_MIN_CONFIDENCE
        )

        # Start from deterministic, explainable rule evidence. An AI-only
        # positive verdict must not promote a benign notification or an
        # ordinary URL into SUSPICIOUS/HIGH RISK by itself.
        final_score = baseline
        if baseline >= self.RULE_HIGH_SCORE:
            final_level = "HIGH RISK"
        elif baseline >= 30:
            final_level = "SUSPICIOUS"
        else:
            final_level = "LOW RISK"

        if ai_positive and ai_corroborated and baseline < self.RULE_HIGH_SCORE:
            final_score = max(baseline, self.AI_CONFIRMED_MIN_SCORE)
            final_level = "HIGH RISK"
            evidence.append(
                "AI verdict corroborated: the model reported likely_scam=True with confidence >= 75 and the rule engine independently found at least 35/100 risk points. Final classification raised to HIGH RISK."
            )
        elif ai_positive:
            evidence.append(
                "AI-only concern is unconfirmed: the model's positive verdict was not supported by enough independent rule evidence, so it did not raise the final risk score or level. Check the explanation and verify unexpected requests through an independently obtained official channel."
            )
        elif ai_available and prediction is False:
            evidence.append(
                "AI verdict: likely_scam=False. It does not erase independent rule-based risk indicators."
            )
        elif ai_available:
            evidence.append("AI verdict missing or invalid; retaining the rule-based assessment.")
        else:
            evidence.append("AI unavailable; retaining the rule-based assessment.")

        rule_category_value = (
            rule_category.strip()
            if isinstance(rule_category, str) and rule_category.strip()
            else "General Message"
        )
        final_category = rule_category_value
        link_only_categories = {
            "URL Present - Needs Verification",
            "URL Present",
            "Message Contains URL",
        }
        if baseline < 30 and final_category in link_only_categories:
            # A bare URL is not itself a scam category. URL reputation and
            # concrete message indicators are still shown separately.
            final_category = "General Message"
            evidence.append("A URL was present, but link presence alone did not justify a scam category.")
        if ai_corroborated and scam_type and final_category in self.GENERIC_CATEGORIES:
            final_category = scam_type
            evidence.append(f"AI scam type used as supporting category: {scam_type}")

        # Only a verified reputation hit can override clean-looking message
        # content independently. An unverified report or no-match is not proof.
        if reputation_status == "confirmed_malicious":
            final_score = max(final_score, self.VERIFIED_URL_MIN_SCORE)
            final_level = "HIGH RISK"
            if final_category in self.GENERIC_CATEGORIES or final_category == "Suspicious URL Indicators":
                final_category = "Confirmed Malicious URL"
            evidence.append(
                "VERIFIED URL THREAT: the reputation provider returned a verified phishing match; final score forced to at least 98/100."
            )

        return {
            "score": final_score,
            "level": final_level,
            "category": final_category,
            "evidence": evidence,
            # Keep the existing field, but define support as corroboration,
            # not merely a model returning true.
            "ai_supported": ai_corroborated,
            "ai_model_prediction": prediction,
            "ai_model_confidence": confidence,
            "ai_verdict_corroborated": ai_corroborated,
            "url_score": url_score,
            "url_reputation_status": reputation_status,
        }
