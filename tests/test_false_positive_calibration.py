import unittest

from core.fusion_engine import EvidenceFusion


class FalsePositiveCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.fusion = EvidenceFusion()

    @staticmethod
    def ai(prediction=True, confidence=95, available=True, scam_type="Phishing"):
        return {
            "available": available,
            "result": {
                "likely_scam": prediction,
                "confidence": confidence,
                "scam_type": scam_type,
            },
        }

    @staticmethod
    def clean_url(status="no_known_threats"):
        return {
            "success": True,
            "score": 0,
            "level": "LOW RISK",
            "signals": [],
            "reputation_status": status,
        }

    def combine(self, rule_score=0, rule_category="No Strong Rule Indicators", ai=None, url=None):
        return self.fusion.combine(
            rule_score=rule_score,
            rule_level="",
            rule_category=rule_category,
            ai_analysis=ai if ai is not None else self.ai(),
            url_analysis=url if url is not None else self.clean_url(),
        )

    def test_ai_only_positive_does_not_flag_benign_feedback_message_as_high_risk(self):
        # Equivalent to the Vi feedback example: a plain service-survey request
        # with one URL and no request for money, credentials, PIN, or OTP.
        result = self.combine(rule_score=0, ai=self.ai(True, 98))
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "LOW RISK")
        self.assertFalse(result["ai_supported"])
        self.assertTrue(any("AI-only concern is unconfirmed" in item for item in result["evidence"]))

    def test_ai_only_positive_does_not_upgrade_ordinary_brand_notification(self):
        result = self.combine(rule_score=8, ai=self.ai(True, 99))
        self.assertEqual(result["score"], 8)
        self.assertEqual(result["level"], "LOW RISK")

    def test_model_positive_plus_strong_independent_rules_can_raise_risk(self):
        result = self.combine(rule_score=40, rule_category="Phishing / Credential Theft", ai=self.ai(True, 90))
        self.assertEqual(result["score"], 60)
        self.assertEqual(result["level"], "HIGH RISK")
        self.assertTrue(result["ai_supported"])

    def test_low_confidence_ai_does_not_promote_suspicious_rules_to_high(self):
        result = self.combine(rule_score=40, ai=self.ai(True, 55))
        self.assertEqual(result["score"], 40)
        self.assertEqual(result["level"], "SUSPICIOUS")
        self.assertFalse(result["ai_supported"])

    def test_ai_negative_does_not_erase_high_rule_score(self):
        result = self.combine(rule_score=72, ai=self.ai(False, 94))
        self.assertEqual(result["score"], 72)
        self.assertEqual(result["level"], "HIGH RISK")

    def test_confirmed_malicious_url_still_forces_high_risk(self):
        malicious = {"success": True, "score": 100, "signals": ["confirmed_malicious_url"], "reputation_status": "confirmed_malicious"}
        result = self.combine(rule_score=0, ai=self.ai(False, 95), url=malicious)
        self.assertEqual(result["score"], 98)
        self.assertEqual(result["level"], "HIGH RISK")
        self.assertEqual(result["category"], "Confirmed Malicious URL")

    def test_unverified_or_no_match_reputation_does_not_force_high_risk(self):
        for status in ("no_known_threats", "reported_unverified", "unavailable"):
            with self.subTest(status=status):
                result = self.combine(rule_score=0, ai=self.ai(True, 99), url=self.clean_url(status))
                self.assertEqual(result["score"], 0)
                self.assertEqual(result["level"], "LOW RISK")

    def test_ai_scam_type_is_not_used_as_final_category_without_corroboration(self):
        result = self.combine(rule_score=0, rule_category="General Message", ai=self.ai(True, 99))
        self.assertEqual(result["category"], "General Message")

    def test_bare_url_category_is_normalised_without_flagging_scam(self):
        result = self.combine(
            rule_score=0,
            rule_category="URL Present - Needs Verification",
            ai=self.ai(True, 99),
        )
        self.assertEqual(result["level"], "LOW RISK")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["category"], "General Message")


if __name__ == "__main__":
    unittest.main(verbosity=2)
