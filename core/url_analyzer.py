from __future__ import annotations

import ipaddress
import json
import os
import re
import ssl
import threading
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from typing import Any

try:
    import truststore
except ImportError:  # optional; install truststore in the runtime for Windows store support
    truststore = None


class URLAnalyzer:
    """Conservative URL analysis plus an optional public reputation lookup.

    Reputation states are intentionally distinct:
      - confirmed_malicious: the provider returned a verified phishing match
      - no_known_threats: the provider responded and did not find a match
      - reported_unverified: the provider found a record that is not verified
      - unavailable: the provider could not be reached or returned bad data
      - not_checked: external reputation lookup has been disabled

    A no_known_threats result is NOT a guarantee that a URL is safe.
    The provider receives the normalized hostname and path. Query strings and
    fragments are omitted by default to reduce accidental exposure of tokens.
    Set SCAMSHIELD_URL_LOOKUP_INCLUDE_QUERY=1 to opt in to sending query strings.
    Set SCAMSHIELD_URL_REPUTATION_ENABLED=0 to disable network lookups entirely.
    """

    REPUTATION_ENDPOINT = "https://openphish.eu/api/check"
    REPUTATION_PROVIDER = "openphish.eu"
    USER_AGENT = "ScamShield-URL-Analyzer/1.0 (local reputation lookup)"
    LOOKUP_TIMEOUT_SECONDS = 4.0

    # These are indicators, not proof of fraud. Ordinary words such as login,
    # verify, payment, account, or refund are deliberately NOT scored alone.
    PROTECTED_BRANDS = {
        "sbi": ["sbi.co.in"],
        "hdfc": ["hdfcbank.com"],
        "icici": ["icicibank.com"],
        "axis": ["axisbank.com"],
        "amazon": ["amazon.in", "amazon.com"],
        "flipkart": ["flipkart.com"],
        "paytm": ["paytm.com"],
        "phonepe": ["phonepe.com"],
        "myvi": ["myvi.in"],
        "google": ["google.com"],
    }

    # Terms used only at hostname label boundaries, avoiding broad substring
    # matches such as treating "notgoogleexample.com" as Google impersonation.
    BRAND_LABELS = {
        "sbi": {"sbi", "statebankofindia"},
        "hdfc": {"hdfc", "hdfcbank"},
        "icici": {"icici", "icicibank"},
        "axis": {"axis", "axisbank"},
        "amazon": {"amazon"},
        "flipkart": {"flipkart"},
        "paytm": {"paytm"},
        "phonepe": {"phonepe"},
        "myvi": {"myvi"},
        "google": {"google"},
    }

    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"
    }
    COMMON_PORTS = {80, 443}

    def __init__(self) -> None:
        self._reputation_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._cache_lock = threading.Lock()

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _normalize_input(url: str) -> str:
        value = url.strip()
        if value and not re.match(r"^https?://", value, flags=re.IGNORECASE):
            value = "https://" + value
        return value

    @staticmethod
    def _is_official_domain(hostname: str, official_domains: list[str]) -> bool:
        return any(
            hostname == official or hostname.endswith("." + official)
            for official in official_domains
        )

    def _find_brand_impersonation(self, hostname: str) -> list[str]:
        labels = hostname.rstrip(".").lower().split(".")
        matches: list[str] = []
        for brand, official_domains in self.PROTECTED_BRANDS.items():
            if self._is_official_domain(hostname, official_domains):
                continue

            known_labels = self.BRAND_LABELS.get(brand, {brand})
            found = False
            for label in labels:
                # Exact brand-like tokens or hyphen-separated label parts only.
                parts = set(label.split("-"))
                compact = label.replace("-", "")
                if parts.intersection(known_labels) or compact in known_labels:
                    found = True
                    break
                # Handle labels such as "sbi-login-verify" without treating
                # arbitrary substrings such as "notgoogleexample" as a match.
                if any(label.startswith(term + "-") for term in known_labels):
                    found = True
                    break
            if found:
                matches.append(brand)
        return matches

    def _build_lookup_url(self, parsed: Any, hostname: str) -> str:
        """Build a safe-to-send reputation URL, excluding credentials/fragments."""
        include_query = os.getenv("SCAMSHIELD_URL_LOOKUP_INCLUDE_QUERY", "0").strip().lower() in {
            "1", "true", "yes", "on"
        }
        scheme = parsed.scheme.lower()
        port = parsed.port
        netloc = hostname
        if port is not None and not (
            (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        ):
            netloc = f"{hostname}:{port}"
        path = parsed.path or "/"
        query = parsed.query if include_query else ""
        return urlunsplit((scheme, netloc, path, query, ""))

    def _query_reputation(self, lookup_url: str) -> dict[str, Any]:
        """Query the documented openphish.eu API. Never visit the target URL."""
        cache_key = lookup_url
        now = time.monotonic()
        with self._cache_lock:
            cached = self._reputation_cache.get(cache_key)
            if cached and cached[0] > now:
                return dict(cached[1])

        api_url = self.REPUTATION_ENDPOINT + "?" + urlencode({"url": lookup_url})
        request = Request(api_url, headers={"User-Agent": self.USER_AGENT, "Accept": "application/json"})

        try:
            # Use Windows' native certificate store when truststore is installed.
            # Certificate verification stays enabled; this is not an SSL bypass.
            ssl_context = (
                truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if truststore is not None
                else None
            )
            open_kwargs: dict[str, object] = {"timeout": self.LOOKUP_TIMEOUT_SECONDS}
            if ssl_context is not None:
                open_kwargs["context"] = ssl_context

            with urlopen(request, **open_kwargs) as response:
                if getattr(response, "status", 200) != 200:
                    raise URLError(f"Reputation provider returned HTTP {response.status}")
                raw_data = response.read(512 * 1024 + 1)
                if len(raw_data) > 512 * 1024:
                    raise ValueError("Reputation response exceeded the size limit")
            payload = json.loads(raw_data.decode("utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("found"), bool):
                raise ValueError("Unexpected reputation response format")

            if payload["found"]:
                phish = payload.get("phish") if isinstance(payload.get("phish"), dict) else {}
                source_status = str(phish.get("status", "")).strip().lower()
                if source_status == "verified":
                    result = {
                        "reputation_status": "confirmed_malicious",
                        "reputation_provider": self.REPUTATION_PROVIDER,
                        "reputation_detail": "A verified phishing match was returned by the reputation provider.",
                        "reputation_checked_at": self._utc_now(),
                    }
                    ttl = 300
                else:
                    result = {
                        "reputation_status": "reported_unverified",
                        "reputation_provider": self.REPUTATION_PROVIDER,
                        "reputation_detail": "A record exists, but the provider did not mark it verified; it is not treated as a confirmed threat.",
                        "reputation_checked_at": self._utc_now(),
                    }
                    ttl = 180
            else:
                result = {
                    "reputation_status": "no_known_threats",
                    "reputation_provider": self.REPUTATION_PROVIDER,
                    "reputation_detail": "No matching verified threat was found in this provider's database. This does not guarantee safety.",
                    "reputation_checked_at": self._utc_now(),
                }
                ttl = 900

        except HTTPError as exc:
            status = "rate_limited" if exc.code == 429 else "provider_http_error"
            result = {
                "reputation_status": "unavailable",
                "reputation_provider": self.REPUTATION_PROVIDER,
                "reputation_detail": f"Reputation lookup unavailable ({status}, HTTP {exc.code}); local analysis was used.",
                "reputation_checked_at": self._utc_now(),
            }
            ttl = 45
        except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
            result = {
                "reputation_status": "unavailable",
                "reputation_provider": self.REPUTATION_PROVIDER,
                "reputation_detail": f"Reputation lookup unavailable ({type(exc).__name__}); local analysis was used.",
                "reputation_checked_at": self._utc_now(),
            }
            ttl = 45
        except Exception as exc:
            # A provider issue must never prevent the message-level analysis.
            result = {
                "reputation_status": "unavailable",
                "reputation_provider": self.REPUTATION_PROVIDER,
                "reputation_detail": f"Reputation lookup failed ({type(exc).__name__}); local analysis was used.",
                "reputation_checked_at": self._utc_now(),
            }
            ttl = 45

        with self._cache_lock:
            self._reputation_cache[cache_key] = (time.monotonic() + ttl, dict(result))
            # Prevent an unbounded in-memory cache in a long-running API process.
            if len(self._reputation_cache) > 2048:
                expired = [key for key, (expires, _) in self._reputation_cache.items() if expires <= time.monotonic()]
                for key in expired:
                    self._reputation_cache.pop(key, None)
                if len(self._reputation_cache) > 2048:
                    for key in list(self._reputation_cache)[: len(self._reputation_cache) - 1024]:
                        self._reputation_cache.pop(key, None)
        return dict(result)

    def analyze(self, url: str) -> dict[str, Any]:
        if not isinstance(url, str) or not url.strip():
            return {
                "success": False,
                "score": 0,
                "level": "LOW RISK",
                "signals": [],
                "reasons": [],
                "reputation_status": "invalid_url",
                "reputation_provider": None,
                "reputation_detail": "No URL was provided.",
            }

        normalized_url = self._normalize_input(url)
        try:
            parsed = urlsplit(normalized_url)
            # Accessing .port validates malformed port values.
            port = parsed.port
            hostname_raw = parsed.hostname
        except ValueError:
            return {
                "success": False,
                "url": normalized_url,
                "score": 30,
                "level": "SUSPICIOUS",
                "signals": ["invalid_url"],
                "reasons": ["The URL could not be parsed correctly."],
                "reputation_status": "invalid_url",
                "reputation_provider": None,
                "reputation_detail": "The URL was not sent to the reputation provider because it could not be parsed.",
            }

        if parsed.scheme.lower() not in {"http", "https"} or not hostname_raw:
            return {
                "success": False,
                "url": normalized_url,
                "score": 30,
                "level": "SUSPICIOUS",
                "signals": ["invalid_url"],
                "reasons": ["Provide a valid HTTP or HTTPS URL with a hostname."],
                "reputation_status": "invalid_url",
                "reputation_provider": None,
                "reputation_detail": "The URL was not sent to the reputation provider because it is invalid.",
            }

        try:
            hostname = hostname_raw.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError:
            hostname = hostname_raw.lower().rstrip(".")

        score = 0
        signals: list[str] = []
        reasons: list[str] = []

        def add(points: int, signal: str, reason: str) -> None:
            nonlocal score
            if signal not in signals:
                signals.append(signal)
                score += points
                reasons.append(reason)

        # 1. Direct IP address: a risk indicator, but not conclusive proof.
        try:
            ipaddress.ip_address(hostname)
            add(25, "ip_address_host", "The link uses an IP address instead of a conventional domain name.")
        except ValueError:
            pass

        # 2. HTTP is weaker transport protection, not by itself evidence of fraud.
        if parsed.scheme.lower() == "http":
            add(5, "insecure_http", "The link uses HTTP rather than HTTPS; this alone does not prove fraud.")

        # 3. Only treat @ in the authority/user-info as suspicious, not an @ in the path.
        if parsed.username is not None or parsed.password is not None:
            add(30, "userinfo_in_url", "The URL embeds user-info before the hostname, which can disguise the destination.")

        # 4. Conservative structural indicators.
        if len(normalized_url) > 180:
            add(5, "long_url", "The URL is unusually long. Length alone is a weak indicator.")

        labels = hostname.split(".")
        if max(0, len(labels) - 2) >= 3:
            add(8, "excessive_subdomains", "The hostname contains three or more subdomain levels; check the registrable domain.")

        if hostname.count("-") >= 3:
            add(5, "hyphen_heavy_domain", "The hostname contains several hyphens; this is a weak indicator by itself.")

        if any(label.startswith("xn--") for label in labels):
            add(15, "punycode_domain", "The domain contains an internationalized punycode label that warrants closer inspection.")

        if hostname in self.SHORTENER_DOMAINS:
            add(5, "url_shortener", "The URL uses a shortening service, so its destination is not obvious from the short link alone.")

        brand_matches = self._find_brand_impersonation(hostname)
        if brand_matches:
            add(
                25,
                "possible_brand_impersonation",
                "The hostname contains a brand-like label but is not one of the brand's listed official domains: "
                + ", ".join(brand_matches)
                + ". This is an indicator, not proof of fraud.",
            )

        try:
            if port is not None and port not in self.COMMON_PORTS:
                add(10, "unusual_port", "The URL uses a non-standard HTTP/HTTPS port.")
        except ValueError:
            add(10, "invalid_port", "The URL contains an invalid port.")

        # Reputation lookup does not send fragments and omits query strings by default.
        if os.getenv("SCAMSHIELD_URL_REPUTATION_ENABLED", "1").strip().lower() in {"0", "false", "no", "off"}:
            reputation = {
                "reputation_status": "not_checked",
                "reputation_provider": None,
                "reputation_detail": "External reputation lookup is disabled; only local URL indicators were evaluated.",
                "reputation_checked_at": None,
            }
        else:
            lookup_url = self._build_lookup_url(parsed, hostname)
            reputation = self._query_reputation(lookup_url)

        reputation_status = reputation.get("reputation_status", "unavailable")
        if reputation_status == "confirmed_malicious":
            score = 100
            if "confirmed_malicious_url" not in signals:
                signals.append("confirmed_malicious_url")
                reasons.append("The reputation provider returned a verified phishing URL match.")
        elif reputation_status == "reported_unverified":
            if "reported_unverified_url" not in signals:
                signals.append("reported_unverified_url")
                reasons.append("A community record was found but is not verified; it is not treated as a confirmed threat.")

        score = max(0, min(100, int(score)))
        if reputation_status == "confirmed_malicious" or score >= 60:
            level = "HIGH RISK"
        elif score >= 30:
            level = "SUSPICIOUS"
        else:
            level = "LOW RISK"

        return {
            "success": True,
            "url": normalized_url,
            "domain": hostname,
            "score": score,
            "level": level,
            "signals": signals,
            "reasons": reasons,
            "reputation_status": reputation_status,
            "reputation_provider": reputation.get("reputation_provider"),
            "reputation_detail": reputation.get("reputation_detail", "Reputation status unavailable."),
            "reputation_checked_at": reputation.get("reputation_checked_at"),
        }


if __name__ == "__main__":
    analyzer = URLAnalyzer()
    test_urls = [
        "https://www.google.com",
        "https://example.com/login/verify",
        "http://192.168.1.50/login",
        "https://sbi-login-verify.example.com/kyc",
        "https://paypal.com@evil.example/path",
    ]
    for test_url in test_urls:
        result = analyzer.analyze(test_url)
        print("\n==============================")
        print(f"URL                : {test_url}")
        print(f"Score              : {result['score']}/100")
        print(f"Level              : {result['level']}")
        print(f"Reputation         : {result.get('reputation_status')}")
        print(f"Reputation details : {result.get('reputation_detail')}")
        print("Signals:", ", ".join(result["signals"]) or "none")
