import unittest
from unittest.mock import Mock

from core.analyzer import ScamAnalyzer
from core.risk_engine import RiskResult


class EngineAlignmentIntegrationTests(unittest.TestCase):
    @staticmethod
    def ai(prediction=True, confidence=97, scam_type="phishing", explanation="This short link is frequently used in phishing."):
        return {
            "available": True,
            "status": "success",
            "provider": "ollama",
            "result": {
                "likely_scam": prediction,
                "scam_type": scam_type,
                "confidence": confidence,
                "confidence_source": "llm",
                "manipulation_tactics": ["obfuscated link"],
                "explanation": explanation,
                "recommended_action": "Do not click.",
            },
        }

    def setup_analyzer(self, *, rule_score=0, rule_level="LOW RISK", rule_category="General Message",
                       rule_signals=None, ai=None, url_status="no_known_threats", url_score=0):
        analyzer = ScamAnalyzer()
        analyzer.url_analyzer.analyze = Mock(return_value={
            "success": True, "score": url_score, "level": "LOW RISK", "signals": [],
            "reasons": [], "domain": "example.test", "reputation_status": url_status,
            "url": "https://example.test/",
        })
        analyzer.risk_engine.analyze = Mock(return_value=RiskResult(
            score=rule_score, level=rule_level, category=rule_category,
            signals=rule_signals or ["contains_url"], reasons=[], actions=[]
        ))
        analyzer._analyze_with_ai = Mock(return_value=ai or self.ai())
        return analyzer

    def test_benign_url_ai_only_alarm_keeps_low_score_and_neutralizes_explanation(self):
        analyzer = self.setup_analyzer()
        result = analyzer.analyze("Hello, share feedback here https://example.test/")
        self.assertTrue(result["success"])
        self.assertEqual(result["final_score"], 0)
        self.assertEqual(result["final_level"], "LOW RISK")
        self.assertEqual(result["final_category"], "General Message")
        shown = result["ai_analysis"]["result"]
        self.assertEqual(shown["scam_type"], "Unconfirmed AI concern")
        self.assertNotIn("frequently used in phishing", shown["explanation"])
        self.assertTrue(result["ai_analysis"]["raw_model_result"]["likely_scam"])

    def test_high_rule_risk_is_not_erased_by_negative_ai(self):
        analyzer = self.setup_analyzer(rule_score=72, rule_level="HIGH RISK", rule_category="Phishing / Credential Theft",
                                       rule_signals=["credential_request"], ai=self.ai(False))
        result = analyzer.analyze("Send your OTP https://example.test/")
        self.assertEqual(result["final_score"], 72)
        self.assertEqual(result["final_level"], "HIGH RISK")

    def test_positive_ai_needs_independent_rule_support_to_escalate(self):
        analyzer = self.setup_analyzer(rule_score=8, rule_level="LOW RISK", rule_category="General Message",
                                       rule_signals=["contains_url", "urgency"], ai=self.ai(True, 99))
        result = analyzer.analyze("Click quickly https://example.test/")
        self.assertEqual(result["final_score"], 8)
        self.assertEqual(result["final_level"], "LOW RISK")
        self.assertEqual(result["ai_analysis"]["result"]["scam_type"], "Unconfirmed AI concern")

    def test_confirmed_malicious_url_forces_high_risk_even_if_message_is_benign(self):
        analyzer = self.setup_analyzer(url_status="confirmed_malicious", url_score=100, ai=self.ai(False))
        result = analyzer.analyze("https://example.test/")
        self.assertEqual(result["final_score"], 98)
        self.assertEqual(result["final_level"], "HIGH RISK")
        self.assertEqual(result["final_category"], "Confirmed Malicious URL")

    def test_rule_and_ai_corroboration_can_raise_risk(self):
        analyzer = self.setup_analyzer(rule_score=40, rule_level="SUSPICIOUS", rule_category="Phishing / Credential Theft",
                                       rule_signals=["credential_request"], ai=self.ai(True, 90))
        result = analyzer.analyze("Please provide your OTP https://example.test/")
        self.assertEqual(result["final_score"], 60)
        self.assertEqual(result["final_level"], "HIGH RISK")
        self.assertTrue(result["fusion_evidence"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
