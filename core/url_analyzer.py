from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


class URLAnalyzer:

    SUSPICIOUS_KEYWORDS = [
        "login",
        "verify",
        "verification",
        "update",
        "secure",
        "account",
        "kyc",
        "refund",
        "payment",
        "wallet",
        "password",
        "otp",
        "claim",
        "reward",
        "prize",
    ]

    # Organizations frequently impersonated in messages.
    # This is NOT a whitelist of legitimate domains.
    PROTECTED_BRANDS = {
        "sbi": ["sbi.co.in"],
        "hdfc": ["hdfcbank.com"],
        "icici": ["icicibank.com"],
        "axis": ["axisbank.com"],
        "amazon": ["amazon.in", "amazon.com"],
        "flipkart": ["flipkart.com"],
        "paytm": ["paytm.com"],
        "phonepe": ["phonepe.com"],
        "google": ["google.com"],
    }

    SHORTENER_DOMAINS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "rb.gy",
    }

    COMMON_PORTS = {80, 443}

    URL_PATTERN = re.compile(
        r"(https?://|www\.)\S+",
        re.IGNORECASE,
    )

    def analyze(self, url: str) -> dict:

        if not url or not url.strip():
            return {
                "success": False,
                "score": 0,
                "level": "LOW RISK",
                "signals": [],
                "reasons": [],
            }

        url = url.strip()

        parsed_url = urlparse(
            url if "://" in url else f"https://{url}"
        )

        domain = parsed_url.hostname

        if not domain:
            return {
                "success": False,
                "score": 40,
                "level": "SUSPICIOUS",
                "signals": ["invalid_url"],
                "reasons": [
                    "The URL could not be parsed correctly."
                ],
            }

        domain = domain.lower()

        score = 0
        signals = []
        reasons = []

        # -----------------------------------------
        # 1. IP ADDRESS
        # -----------------------------------------

        try:
            ipaddress.ip_address(domain)

            score += 35

            signals.append("ip_address_host")

            reasons.append(
                "The link uses an IP address instead of a normal domain name."
            )

        except ValueError:
            pass

        # -----------------------------------------
        # 2. HTTP
        # -----------------------------------------

        if parsed_url.scheme.lower() == "http":

            score += 15

            signals.append("insecure_http")

            reasons.append(
                "The link uses HTTP instead of HTTPS."
            )

        # -----------------------------------------
        # 3. @ SYMBOL
        # -----------------------------------------

        if "@" in url:

            score += 30

            signals.append("at_symbol")

            reasons.append(
                "The URL contains '@', which can be used to disguise the destination."
            )

        # -----------------------------------------
        # 4. LONG URL
        # -----------------------------------------

        if len(url) > 100:

            score += 10

            signals.append("long_url")

            reasons.append(
                "The URL is unusually long."
            )

        # -----------------------------------------
        # 5. SUBDOMAINS
        # -----------------------------------------

        parts = domain.split(".")

        subdomain_count = max(0, len(parts) - 2)

        if subdomain_count >= 3:

            score += 15

            signals.append("excessive_subdomains")

            reasons.append(
                "The hostname contains an unusually large number of subdomains."
            )

        # -----------------------------------------
        # 6. MANY HYPHENS
        # -----------------------------------------

        hyphen_count = domain.count("-")

        if hyphen_count >= 2:

            score += 10

            signals.append("hyphen_heavy_domain")

            reasons.append(
                "The domain contains multiple hyphens, which can occur in deceptive look-alike domains."
            )

        # -----------------------------------------
        # 7. PUNYCODE
        # -----------------------------------------

        if domain.startswith("xn--") or ".xn--" in domain:

            score += 25

            signals.append("punycode_domain")

            reasons.append(
                "The domain uses punycode, which can be used for look-alike domains."
            )

        # -----------------------------------------
        # 8. SUSPICIOUS KEYWORDS
        # -----------------------------------------

        found_keywords = [
            keyword
            for keyword in self.SUSPICIOUS_KEYWORDS
            if keyword in url.lower()
        ]

        if found_keywords:

            score += min(20, len(found_keywords) * 5)

            signals.append("suspicious_keywords")

            reasons.append(
                "The URL contains words commonly associated with account, identity, or payment actions."
            )

        # -----------------------------------------
        # 9. URL SHORTENER
        # -----------------------------------------

        if domain in self.SHORTENER_DOMAINS:

            score += 20

            signals.append("url_shortener")

            reasons.append(
                "The URL uses a shortening service, hiding the final destination."
            )

        # -----------------------------------------
        # 10. POSSIBLE BRAND IMPERSONATION
        # -----------------------------------------

        brand_matches = []

        for brand, legitimate_domains in self.PROTECTED_BRANDS.items():

            if brand in domain:

                # Check whether the actual hostname ends with
                # one of the known legitimate domains.

                is_legitimate_domain = any(
                    domain == legitimate_domain
                    or domain.endswith("." + legitimate_domain)
                    for legitimate_domain in legitimate_domains
                )

                if not is_legitimate_domain:

                    brand_matches.append(brand)

        if brand_matches:

            score += 30

            signals.append("possible_brand_impersonation")

            reasons.append(
                "The hostname appears to reference a recognizable brand "
                "but does not match one of its known domain patterns."
            )

        # -----------------------------------------
        # 11. UNUSUAL PORT
        # -----------------------------------------

        try:

            if (
                parsed_url.port is not None
                and parsed_url.port not in self.COMMON_PORTS
            ):

                score += 15

                signals.append("unusual_port")

                reasons.append(
                    "The URL uses an unusual network port."
                )

        except ValueError:

            score += 15

            signals.append("invalid_port")

            reasons.append(
                "The URL contains an invalid port."
            )

        # -----------------------------------------
        # FINAL SCORE
        # -----------------------------------------

        score = min(score, 100)

        if score >= 60:
            level = "HIGH RISK"

        elif score >= 30:
            level = "SUSPICIOUS"

        else:
            level = "LOW RISK"

        return {
            "success": True,
            "url": url,
            "domain": domain,
            "score": score,
            "level": level,
            "signals": signals,
            "reasons": reasons,
        }


if __name__ == "__main__":

    analyzer = URLAnalyzer()

    test_urls = [
        "https://sbi-login-verify.example.com/kyc",
        "http://192.168.1.50/login",
        "https://bit.ly/claim-reward",
        "https://www.google.com",
    ]

    for url in test_urls:

        result = analyzer.analyze(url)

        print("\n==============================")
        print(f"URL   : {url}")
        print(f"Score : {result['score']}/100")
        print(f"Level : {result['level']}")

        print("\nSignals:")

        for signal in result["signals"]:
            print(f"- {signal}")

        print("\nReasons:")

        for reason in result["reasons"]:
            print(f"- {reason}")