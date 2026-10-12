from __future__ import annotations

from typing import Any


def normalize_uncorroborated_ai_display(
    ai_result: dict[str, Any],
    fusion_result: dict[str, Any],
    url_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Align the displayed AI narrative with independently fused evidence.

    This changes only the user-facing AI narrative. It does not change the
    final score, risk level, or category computed by EvidenceFusion. The raw
    model result is retained under ``raw_model_result`` for technical review.
    """
    if not isinstance(ai_result, dict) or not isinstance(fusion_result, dict):
        return ai_result
    if ai_result.get("available") is not True:
        return ai_result
    if fusion_result.get("ai_verdict_corroborated") is True:
        return ai_result

    model_result = ai_result.get("result")
    if not isinstance(model_result, dict) or model_result.get("likely_scam") is not True:
        return ai_result

    reputation_status = "unknown"
    if isinstance(url_result, dict):
        reputation_status = str(url_result.get("reputation_status", "unknown"))

    if reputation_status == "no_known_threats":
        reputation_context = (
            "The reputation provider found no matching known threat; that is not a guarantee of safety."
        )
    elif reputation_status == "confirmed_malicious":
        reputation_context = (
            "The reputation provider reports a confirmed malicious URL match. This supports the overall "
            "risk assessment, but does not independently validate every claim in the AI's narrative."
        )
    elif reputation_status in {"unavailable", "unknown", "reported_unverified", ""}:
        reputation_context = "The URL reputation result is unavailable or inconclusive."
    else:
        reputation_context = "The URL reputation result is not conclusive."

    overall_level = str(fusion_result.get("level", "")).upper()

    if overall_level == "HIGH RISK":
        explanation = (
            "The AI's specific phishing claim was not independently corroborated. The overall HIGH RISK "
            "rating comes from separate rule/URL evidence shown in the main assessment; use those signals "
            "to understand the rating. A shortened or unfamiliar link alone does not prove fraud. "
            + reputation_context
            + " Verify unexpected requests through an official app or website reached independently."
        )
        action = (
            "Review the independent rule and URL evidence supporting the overall risk rating. If the "
            "message requests money or sensitive information, verify through an official channel reached independently."
        )
    else:
        explanation = (
            "The AI model raised a possible concern, but independent message rules and URL checks did not "
            "provide enough evidence to confirm a scam. A shortened or unfamiliar link can hide its destination; "
            "that fact alone does not establish fraud. "
            + reputation_context
            + " If the message was unexpected, verify it through the organisation's official app or website "
            "reached independently, rather than through the message link."
        )
        action = (
            "This is an unconfirmed AI concern, not a confirmed scam. If you were not expecting the message, "
            "verify it through an official app or website you open independently. Do not enter passwords, PINs, "
            "or OTPs through an unexpected link."
        )

    safe_ai_result = dict(ai_result)
    raw_model_result = safe_ai_result.get("raw_model_result")
    if not isinstance(raw_model_result, dict):
        safe_ai_result["raw_model_result"] = dict(model_result)

    displayed_result = dict(model_result)
    displayed_result.update(
        {
            "likely_scam": False,
            "model_likely_scam": True,
            "review_status": "uncorroborated_ai_concern",
            "advisory_only": True,
            "scam_type": "Unconfirmed AI concern",
            "confidence": None,
            "confidence_source": "unavailable",
            "manipulation_tactics": [],
            "explanation": explanation,
            "recommended_action": action,
        }
    )
    safe_ai_result["result"] = displayed_result
    safe_ai_result["display_review_status"] = "uncorroborated_ai_concern"
    return safe_ai_result
