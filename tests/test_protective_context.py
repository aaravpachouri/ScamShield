from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from core.risk_engine import RiskEngine
from core.url_analyzer import URLAnalyzer


class ProtectiveContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RiskEngine()

    def test_appended_otp_warning_does_not_suppress_separate_otp_request(self):
        core_message = (
            "Your Vodafone Idea account will be blocked today. "
            "Verify your KYC immediately and enter your OTP: "
            "https://myvi.in.verify-account.example.com/customer-check."
        )
        with_warning = core_message + " Never share your OTP with anyone."

        baseline = self.engine.analyze(core_message)
        with_disclaimer = self.engine.analyze(with_warning)

        self.assertIn("credential_request", baseline.signals)
        self.assertIn("credential_request", with_disclaimer.signals)
        self.assertIn("threat_or_pressure", with_disclaimer.signals)
        self.assertIn("urgency", with_disclaimer.signals)
        self.assertEqual(baseline.score, with_disclaimer.score)

    def test_pure_protective_otp_warning_remains_low_risk(self):
        message = (
            "Security reminder: Never share your OTP, password or UPI PIN with anyone. "
            "If a message seems unusual, contact your bank through its official app."
        )
        result = self.engine.analyze(message)
        self.assertLess(result.score, 30)
        self.assertNotIn("credential_request", result.signals)
        self.assertNotIn("suspicious_upi_request", result.signals)

    def test_protective_investment_advice_does_not_hide_separate_payment_request(self):
        message = (
            "Send money now to unlock the promised reward. "
            "A genuine refund should not require your password."
        )
        result = self.engine.analyze(message)
        self.assertIn("financial_request", result.signals)

    def test_deceptive_myvi_subdomain_is_detected_by_url_structure(self):
        with patch.dict(os.environ, {"SCAMSHIELD_URL_REPUTATION_ENABLED": "0"}):
            result = URLAnalyzer().analyze(
                "https://myvi.in.verify-account.example.com/customer-check"
            )
        self.assertIn("possible_brand_impersonation", result["signals"])
        self.assertIn("excessive_subdomains", result["signals"])
        self.assertGreaterEqual(result["score"], 30)

    def test_official_myvi_domain_is_not_marked_as_brand_impersonation(self):
        with patch.dict(os.environ, {"SCAMSHIELD_URL_REPUTATION_ENABLED": "0"}):
            result = URLAnalyzer().analyze(
                "https://www.myvi.in/help-support/vi-customer-care-number"
            )
        self.assertNotIn("possible_brand_impersonation", result["signals"])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "LOW RISK")


if __name__ == "__main__":
    unittest.main()
