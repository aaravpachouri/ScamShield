import unittest

from core.semantic_explanation import normalize_uncorroborated_ai_display


class SemanticExplanationTests(unittest.TestCase):
    def ai(self, likely_scam=True):
        return {
            "available": True,
            "status": "success",
            "provider": "ollama",
            "result": {
                "likely_scam": likely_scam,
                "scam_type": "phishing",
                "confidence": 97,
                "confidence_source": "llm",
                "manipulation_tactics": ["urgency", "obfuscated link"],
                "explanation": "This shortened URL is frequently used in phishing and malware distribution.",
                "recommended_action": "Do not click the link.",
            },
        }

    def fusion(self, level="LOW RISK", corroborated=False, category="General Message"):
        return {"level": level, "category": category, "ai_verdict_corroborated": corroborated}

    def test_unconfirmed_ai_alarm_is_neutralized_for_display(self):
        ai = self.ai(True)
        result = normalize_uncorroborated_ai_display(
            ai, self.fusion(), {"reputation_status": "no_known_threats", "score": 0}
        )
        shown = result["result"]
        self.assertEqual(shown["scam_type"], "Unconfirmed AI concern")
        self.assertFalse(shown["likely_scam"])
        self.assertTrue(shown["model_likely_scam"])
        self.assertIsNone(shown["confidence"])
        self.assertEqual(shown["manipulation_tactics"], [])
        self.assertIn("does not establish fraud", shown["explanation"])
        self.assertIn("not a guarantee of safety", shown["explanation"])
        self.assertNotIn("frequently used in phishing", shown["explanation"])
        self.assertTrue(result["raw_model_result"]["likely_scam"])

    def test_unavailable_reputation_is_not_described_as_safe(self):
        result = normalize_uncorroborated_ai_display(
            self.ai(True), self.fusion(), {"reputation_status": "unavailable"}
        )
        explanation = result["result"]["explanation"]
        self.assertIn("unavailable or inconclusive", explanation)
        self.assertNotIn("no matching known threat", explanation)

    def test_unconfirmed_ai_narrative_is_normalized_even_when_rules_make_overall_high(self):
        result = normalize_uncorroborated_ai_display(
            self.ai(True), self.fusion("HIGH RISK", False, "Suspicious Delivery Fee"),
            {"reputation_status": "no_known_threats", "score": 0},
        )
        shown = result["result"]
        self.assertEqual(shown["scam_type"], "Unconfirmed AI concern")
        self.assertIn("overall HIGH RISK", shown["explanation"])
        self.assertNotIn("classic hallmark", shown["explanation"])

    def test_confirmed_malicious_url_supports_risk_but_not_every_ai_claim(self):
        result = normalize_uncorroborated_ai_display(
            self.ai(True), self.fusion("HIGH RISK", False, "Confirmed Malicious URL"),
            {"reputation_status": "confirmed_malicious"},
        )
        shown = result["result"]
        self.assertEqual(shown["scam_type"], "Unconfirmed AI concern")
        self.assertIn("confirmed malicious URL match", shown["explanation"])
        self.assertTrue(result["raw_model_result"]["likely_scam"])

    def test_negative_model_result_is_left_unchanged(self):
        ai = self.ai(False)
        self.assertIs(normalize_uncorroborated_ai_display(ai, self.fusion(), {"reputation_status": "unknown"}), ai)

    def test_corroborated_ai_result_is_left_unchanged(self):
        ai = self.ai(True)
        self.assertIs(normalize_uncorroborated_ai_display(ai, self.fusion("HIGH RISK", True), {"reputation_status": "no_known_threats"}), ai)


if __name__ == "__main__":
    unittest.main(verbosity=2)
