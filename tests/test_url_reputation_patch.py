from __future__ import annotations

import unittest
from unittest.mock import patch

from core.url_analyzer import URLAnalyzer
from core.fusion_engine import EvidenceFusion


class URLReputationTests(unittest.TestCase):
    def test_ordinary_login_words_do_not_add_url_risk_by_themselves(self) -> None:
        analyzer = URLAnalyzer()
        no_match = {
            "reputation_status": "no_known_threats",
            "reputation_provider": "openphish.eu",
            "reputation_detail": "No matching verified threat was found.",
            "reputation_checked_at": "test",
        }
        with patch.object(analyzer, "_query_reputation", return_value=no_match):
            result = analyzer.analyze("https://example.com/login/verify")
        self.assertTrue(result["success"])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "LOW RISK")
        self.assertEqual(result["reputation_status"], "no_known_threats")

    def test_official_google_domain_stays_low_risk(self) -> None:
        analyzer = URLAnalyzer()
        no_match = {
            "reputation_status": "no_known_threats",
            "reputation_provider": "openphish.eu",
            "reputation_detail": "No matching verified threat was found.",
            "reputation_checked_at": "test",
        }
        with patch.object(analyzer, "_query_reputation", return_value=no_match):
            result = analyzer.analyze("https://www.google.com")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "LOW RISK")

    def test_lookup_omits_query_and_fragment_by_default(self) -> None:
        analyzer = URLAnalyzer()
        no_match = {
            "reputation_status": "no_known_threats",
            "reputation_provider": "openphish.eu",
            "reputation_detail": "No matching verified threat was found.",
            "reputation_checked_at": "test",
        }
        with patch.dict("os.environ", {"SCAMSHIELD_URL_LOOKUP_INCLUDE_QUERY": "0"}):
            with patch.object(analyzer, "_query_reputation", return_value=no_match) as lookup:
                analyzer.analyze("https://example.com/login?session=SECRET#section")
        sent_url = lookup.call_args.args[0]
        self.assertEqual(sent_url, "https://example.com/login")
        self.assertNotIn("SECRET", sent_url)
        self.assertNotIn("#", sent_url)

    def test_verified_threat_is_high_risk(self) -> None:
        analyzer = URLAnalyzer()
        match = {
            "reputation_status": "confirmed_malicious",
            "reputation_provider": "openphish.eu",
            "reputation_detail": "Verified match",
            "reputation_checked_at": "test",
        }
        with patch.object(analyzer, "_query_reputation", return_value=match):
            result = analyzer.analyze("https://bad.example/payload")
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["level"], "HIGH RISK")
        self.assertIn("confirmed_malicious_url", result["signals"])

    def test_unverified_record_does_not_become_confirmed_threat(self) -> None:
        analyzer = URLAnalyzer()
        match = {
            "reputation_status": "reported_unverified",
            "reputation_provider": "openphish.eu",
            "reputation_detail": "Unverified record",
            "reputation_checked_at": "test",
        }
        with patch.object(analyzer, "_query_reputation", return_value=match):
            result = analyzer.analyze("https://maybe.example/path")
        self.assertNotEqual(result["reputation_status"], "confirmed_malicious")
        self.assertLess(result["score"], 60)

    def test_provider_failure_falls_back_without_adding_reputation_points(self) -> None:
        analyzer = URLAnalyzer()
        unavailable = {
            "reputation_status": "unavailable",
            "reputation_provider": "openphish.eu",
            "reputation_detail": "unavailable",
            "reputation_checked_at": "test",
        }
        with patch.object(analyzer, "_query_reputation", return_value=unavailable):
            result = analyzer.analyze("https://example.com/login")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["reputation_status"], "unavailable")

    def test_verified_threat_forces_final_score_even_if_message_looks_clean(self) -> None:
        fusion = EvidenceFusion()
        result = fusion.combine(
            rule_score=0,
            rule_level="LOW RISK",
            rule_category="General Message",
            ai_analysis={"available": True, "result": {"likely_scam": False}},
            url_analysis={
                "success": True,
                "score": 100,
                "reputation_status": "confirmed_malicious",
                "signals": ["confirmed_malicious_url"],
            },
        )
        self.assertEqual(result["score"], 98)
        self.assertEqual(result["level"], "HIGH RISK")
        self.assertEqual(result["category"], "Confirmed Malicious URL")

    def test_no_match_does_not_force_high_risk(self) -> None:
        fusion = EvidenceFusion()
        result = fusion.combine(
            rule_score=0,
            rule_level="LOW RISK",
            rule_category="General Message",
            ai_analysis={"available": False},
            url_analysis={
                "success": True,
                "score": 0,
                "reputation_status": "no_known_threats",
                "signals": [],
            },
        )
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "LOW RISK")


if __name__ == "__main__":
    unittest.main()
