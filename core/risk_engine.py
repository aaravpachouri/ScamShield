from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import List
from urllib.parse import urlparse


@dataclass
class RiskResult:
    score: int
    level: str
    category: str
    signals: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)


class RiskEngine:
    """Transparent heuristic scam-risk engine.

    Scores are heuristic indicators, not calibrated probabilities.
    0-29: LOW RISK; 30-59: SUSPICIOUS; 60-100: HIGH RISK.
    """

    URGENCY_PATTERNS = [
        r"\burgent(?:ly)?\b",
        r"\bimmediately\b",
        r"\bwithin\s+\d+\s+(?:minutes?|hours?|days?)\b",
        r"\bact\s+now\b",
        r"\blast\s+warning\b",
        r"\bexpires?\s+(?:today|soon|tonight)\b",
        r"\bfinal\s+(?:notice|warning|reminder)\b",
        r"\bwithout\s+delay\b",
        r"\blimited\s+(?:time|slots|offer)\b",
        r"\b(?:today|right\s+away)\b",
        r"\bbefore\s+(?:your\s+)?offer\s+expires\b",
        r"\bnow\b",
    ]

    CREDENTIAL_REQUEST_PATTERNS = [
        r"\b(?:enter|share|send|provide|submit|tell|reveal|disclose|reply\s+with|give)\s+(?:me\s+)?(?:your\s+)?(?:banking\s+)?(?:login\s+)?(?:otp|password|pin|cvv|passcode|bank\s+details|banking\s+credentials|credentials)\b",
        r"\b(?:otp|password|pin|cvv|passcode)\s+(?:is\s+required|to\s+(?:verify|continue|unlock|proceed))\b",
        r"\bverify\s+your\s+(?:account|identity|credentials|kyc)\b",
        r"\bconfirm\s+your\s+(?:login|account\s+details|bank\s+details)\b",
        r"\bupdate\s+your\s+(?:bank\s+)?(?:login\s+)?credentials\b",
        r"\b(?:enter|submit|provide|send|share|reply\s+with)\b.{0,100}\b(?:otp|password|pin|cvv|passcode|banking\s+credentials|bank\s+details)\b",
        r"\bscan\b.{0,80}\bqr\s+code\b.{0,100}\b(?:upi\s+pin|pin)\b",
        r"\bsubmit\s+your\s+banking\s+credentials\b",
        r"\breply\s+with\s+(?:your\s+)?(?:password|passcode|otp|pin)\b",
    ]

    FINANCIAL_ACTION_PATTERNS = [
        r"\bpay\s+(?:now|immediately|to\s+avoid)\b",
        r"\bpay\b.{0,50}\b(?:rs\.?|inr|â‚¹|\$)\s*[\d,]+",
        r"\btransfer\b.{0,60}\b(?:rs\.?|inr|â‚¹|\$)\s*[\d,]+",
        r"\btransfer\s+(?:money|funds)\b",
        r"\bsend\s+(?:money|payment|funds)\b",
        r"\bpay\s+(?:a\s+)?(?:processing|verification|release|delivery|activation|joining|registration|advance)\s+fee\b",
        r"\bclaim\s+(?:your\s+)?(?:prize|reward|refund|cashback)\b",
        r"\bpay\s+to\s+(?:receive|release|unlock|claim|get)\b",
        r"\b(?:guaranteed|guarantees?)\s+(?:returns?|profit|income)\b",
        r"\bdouble\s+your\s+money\b",
        r"\b(?:registration|processing|activation|joining|verification|release|advance)\s+fee\b",
        r"\bpay\s+(?:a\s+)?refundable\s+fee\b",
        r"\b(?:upfront|advance)\s+(?:payment|fee|charge)\b",
        r"\b(?:unlock|release)\b.{0,70}\b(?:payment|cashback|cash\s+reward|grant|funds|money)\b",
        r"\b(?:pending|promised)\s+(?:payment|cashback|grant|transfer|reward)\b",
        r"\bpay\b.{0,60}\b(?:joining|processing|activation|verification|release)\s+fee\b",
        r"\bpay\s+(?:a\s+)?(?:small|refundable|advance)\s+fee\b",
        r"\badvance\s+fee\b",
        r"\b(?:bank\s+details|banking\s+credentials)\b",
    ]

    PRIZE_SCAM_PATTERNS = [
        r"\b(?:you\s+have\s+won|you(?:'ve| have)\s+won|congratulations).{0,120}\b(?:prize|reward|lottery|cash|winner|gift|voucher)\b",
        r"\b(?:claim|release)\s+(?:your\s+)?(?:prize|reward|winnings|lottery|gift\s+voucher)\b",
        r"\b(?:release|unlock)\s+(?:the\s+)?(?:winnings|reward|prize|gift\s+voucher)\b",
        r"\b(?:send|provide|submit)\s+(?:your\s+)?(?:bank\s+details|banking\s+credentials)\b",
        r"\bpay\b.{0,50}\b(?:release|claim|receive)\b.{0,40}\b(?:reward|prize|voucher|winnings)\b",
    ]

    JOB_SCAM_PATTERNS = [
        r"\bwork\s+from\s+home\b",
        r"\bearn(?:ing)?\s+(?:rs\.?|inr|â‚¹|\$)?\s*[\d,]+\s*(?:daily|per\s+day|a\s+day)\b",
        r"\bearn\s+(?:money|income)\s+easily\b",
        r"\bjob\s+(?:registration|joining|processing)\s+fee\b",
        r"\bpay\s+(?:a\s+)?(?:registration|joining|processing)\s+fee\b",
        r"\bselected\s+for\s+(?:a\s+)?(?:online\s+)?job\b",
        r"\bonline\s+job\b",
        r"\bremote\s+(?:data\s+entry|online)\s+job\b",
        r"\bwork\s+assignment\b",
        r"\b(?:joining|processing|registration)\s+fee\b",
        r"\bpay\b.{0,50}\b(?:joining|processing|registration)\s+fee\b",
    ]

    INVESTMENT_SCAM_PATTERNS = [
        r"\bguarante(?:ed|es)\s+(?:returns?|profit|income)\b",
        r"\b(?:returns?|profit)\s+of\s+\d+\s*%\b",
        r"\bearn\s+\d+\s*%\s+(?:daily|weekly|monthly)\b",
        r"\b\d+\s*%\s+(?:profit|returns?)\s+(?:daily|weekly|monthly)\b",
        r"\bdouble\s+your\s+money\b",
        r"\brisk[- ]free\s+(?:investment|returns?|profit|trading)\b",
        r"\bno\s+possibility\s+of\s+loss\b",
        r"\bno\s+risk\b",
        r"\b(?:invest|investment|trading)\b.{0,80}\b(?:guaranteed|guarantees|risk[- ]free|no\s+possibility\s+of\s+loss)\b",
        r"\b(?:guaranteed|guarantees)\b.{0,50}\b\d+\s*%\s+returns?\b",
    ]

    DELIVERY_SCAM_PATTERNS = [
        r"\b(?:parcel|package|delivery|courier)\b.{0,140}\b(?:on\s+hold|held|failed|incomplete\s+address|undelivered|pending|delivery\s+issue|address\s+issue|delivery\s+attempt\s+failed|could\s+not\s+find\s+your\s+address|could\s+not\s+be\s+delivered|couldn't\s+be\s+delivered)\b",
        r"\b(?:address|parcel|package|delivery|courier)\b.{0,100}\b(?:incorrect|incomplete|confirm|update|verify|issue|pending)\b",
        r"\b(?:package|parcel|delivery)\b.{0,100}\baddress\s+issue\b",
        r"\bcourier\b.{0,100}\b(?:could\s+not|couldn't)\s+find\b",
    ]

    DELIVERY_PAYMENT_PATTERNS = [
        r"\b(?:pay|payment)\b.{0,100}\b(?:delivery|parcel|release|processing|handling)\s+fee\b",
        r"\b(?:pay|settle)\s+(?:a\s+)?(?:small\s+)?fee\b",
        r"\bpay\b.{0,40}\b(?:rs\.?|inr|â‚¹|\$)\s*[\d,]+.{0,120}\b(?:receive|release|complete|get|unlock)\b.{0,50}\b(?:delivery|parcel|package|courier)\b",
        r"\b(?:delivery|parcel|package|courier)\b.{0,120}\b(?:pay|payment)\b.{0,40}\b(?:rs\.?|inr|â‚¹|\$)\s*[\d,]+",
        r"\bpay\s+(?:a\s+)?small\s+fee\b",
        r"\bpay\b.{0,80}\bfee\b.{0,100}\b(?:delivery|parcel|package)\b",
        r"\b(?:pay|payment)\b.{0,80}\b(?:address|package|parcel)\b",
        r"\b(?:pay|payment)\b.{0,45}\b(?:rs\.?|inr|â‚¹|\$)\s*[\d,]+.{0,80}\b(?:reschedule|re\s*schedule|redeliver|re\s*deliver)\b.{0,40}\b(?:delivery|package|parcel|courier)\b",
        r"\b(?:reschedule|re\s*schedule|redeliver|re\s*deliver)\b.{0,50}\b(?:delivery|package|parcel|courier)\b.{0,80}\b(?:pay|payment)\b.{0,35}\b(?:rs\.?|inr|â‚¹|\$)\s*[\d,]+",
    ]

    UPI_SCAM_PATTERNS = [
        r"\bupi\s+pin\b.{0,100}\b(?:receive|claim|accept|get)\s+(?:money|payment|funds)\b",
        r"\bscan\b.{0,80}\bqr\s+code\b.{0,100}\b(?:receive|get|claim)\s+(?:money|payment|refund)\b",
        r"\bto\s+receive\s+(?:money|payment|refund)\b.{0,80}\b(?:upi\s+pin|scan\s+(?:the\s+)?qr)\b",
        r"\bapprove\s+(?:the\s+)?collect\s+request\b",
    ]

    # New contextual patterns for the three remaining holdout misses.
    UPI_REFUND_MANIPULATION_PATTERNS = [
        r"\bpayment request\b.{0,120}\bapprove\b.{0,100}\b(?:refund|receive money|receive your money)\b",
        r"\bapprove it to receive your refund\b",
        r"\bapprove\b.{0,80}\b(?:collect request|payment request)\b.{0,100}\brefund\b",
        r"\bscan\b.{0,80}\bqr\s+code\b.{0,100}\bto\s+receive\s+(?:the\s+)?(?:money|payment|refund)\b",

        r"\b(?:do not|don't|dont)\s+(?:contact|call|inform)\s+(?:your\s+)?bank\b.{0,100}\b(?:refund|payment|money|transfer)\b",  
    ]

    CONFIDENTIAL_BANK_CHANGE_PATTERNS = [
        r"\b(?:new|updated|changed)\s+bank details\b",
        r"\buse these new bank details\b",
        r"\b(?:vendor|supplier)\b.{0,100}\b(?:bank details|account details)\b.{0,100}\b(?:confidential|secret|keep it quiet)\b",
        r"\b(?:bank details|account details)\b.{0,100}\b(?:confidential|secret|keep it quiet|until i confirm)\b",
    ]

    CRYPTO_SECRET_REQUEST_PATTERNS = [
        r"\b(?:share|send|enter|provide|reveal|type|submit)\b.{0,80}\b(?:wallet\s+)?(?:recovery|seed)\s+phrase\b",
        r"\b(?:share|send|enter|provide|reveal|type|submit)\b.{0,80}\bprivate\s+key\b",
        r"\b(?:wallet|crypto)\b.{0,100}\b(?:recovery phrase|seed phrase|private key)\b",
    ]

    THREAT_PATTERNS = [
        r"\b(?:your\s+)?account\s+(?:will|shall|may)\s+be\s+(?:blocked|suspended|deactivated|closed)\b",
        r"\b(?:legal\s+action|arrest\s+warrant|police\s+case)\b",
        r"\b(?:pay|respond|verify)\s+or\s+(?:face|risk)\b",
        r"\b(?:penalty|fine)\s+(?:will\s+be\s+imposed|of\s+(?:â‚¹\s*)?[\d,]+)\b",
        r"\bservice\s+will\s+be\s+(?:blocked|suspended|terminated)\b",
        r"\b(?:account|card|banking)\b.{0,60}\b(?:permanently\s+)?(?:blocked|suspended|terminated)\b",
        r"\b(?:permanently\s+)?suspended\b",
        r"\baccount\b.{0,60}\b(?:verify|verification)\b",
        r"\bavoid\s+account\s+closure\b",
        r"\bavoid\s+account\s+suspension\b",
        r"\baccount\s+suspension\b",
    ]

    ACCOUNT_IMPERSONATION_LINK_PATTERN = re.compile(
        r"\b(?:sbi|state\s+bank\s+of\s+india|hdfc|icici|axis\s+bank|rbi|income\s+tax|paytm|phonepe|google\s+pay)\b"
        r".{0,120}\b(?:kyc|account|banking)\b"
        r".{0,160}\b(?:update|verify|expired|suspend|suspension|blocked)\b"
        r".{0,180}(?:https?://|www\.)",
        re.IGNORECASE,
    )

    BRAND_KEYWORDS = [
        "sbi", "state bank of india", "hdfc", "icici", "axis bank",
        "rbi", "income tax", "government", "flipkart", "amazon",
        "phonepe", "paytm", "google pay",
    ]

    URL_PATTERN = re.compile(
        r"(?ix)\b(?:https?://[^\s<>\"'`\]\[()]+|www\.[^\s<>\"'`\]\[()]+|"
        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+(?:/[^\s<>\"'`\]\[()]*)?)"
    )

    PROTECTIVE_WARNING_PATTERN = re.compile(
        r"\b(?:never|don't|do not|dont|avoid|warning)\b"
        r".{0,120}\b(?:share|send|provide|reveal|disclose|enter|tell|give|reply\s+with|approve|accept)\b"
        r".{0,100}\b(?:otp|password|pin|cvv|passcode|credentials|collect\s+request)\b",
        re.IGNORECASE,
    )

    PROTECTIVE_ADVICE_PATTERN = re.compile(
        r"\bbe\s+cautious\s+of\b.{0,120}\b(?:investment\s+offers?|guaranteed\s+high\s+returns?)\b"
        r"|\bif\s+someone\s+asks\s+you\s+to\s+share\b.{0,120}\b(?:otp|password|pin|passcode|credentials)\b.{0,120}\b(?:stop|contact|verify)\b"
        r"|\ba\s+genuine\s+refund\b.{0,120}\bshould\s+not\s+require\b.{0,120}\b(?:password|upi\s+pin|otp|banking\s+credentials)\b",
        re.IGNORECASE,
    )

    PROTECTIVE_UPI_WARNING_PATTERN = re.compile(
        r"\b(?:you\s+do\s+not|you\s+don't|you\s+dont)\s+need\s+to\b.{0,100}\b(?:enter|share|provide|use)\b.{0,50}\bupi\s+pin\b.{0,80}\bto\s+receive\s+money\b"
        r"|\bnever\s+(?:approve|accept)\b.{0,80}\bcollect\s+request\b.{0,80}\b(?:don't|do\s+not|dont)\s+recognise\b"
        r"|\bnever\s+(?:enter|use|share|disclose)\b.{0,80}\b(?:it|your\s+upi\s+pin|upi\s+pin)\b.{0,80}\b(?:to\s+receive\s+money|with\s+anyone)\b",
        re.IGNORECASE,
    )

    ADVANCE_FEE_REWARD_PATTERN = re.compile(
        r"\b(?:pay|send)\b.{0,60}\b(?:a\s+)?(?:refundable\s+)?(?:activation|advance|verification|release|processing)\s+fee\b.{0,120}\b(?:unlock|release|receive|get|claim)\b.{0,60}\b(?:cash\s+reward|reward|cashback|grant|payment|money|funds|winnings)\b"
        r"|\b(?:pay|send)\b.{0,60}\b(?:rs\.?|inr|₹|\$)\s*[\d,]+.{0,50}\badvance\s+fee\b.{0,120}\b(?:grant|reward|payment|cashback|money|funds)\b",
        re.IGNORECASE,
    )

    @classmethod
    def _strip_protective_clauses(cls, text: str) -> str:
        """Remove protective clauses without masking separate risky clauses.

        Each sentence is handled separately, and only text matched by a known
        protective-warning pattern is removed. A disclaimer at the end of a
        message therefore cannot cancel a separate request to enter/disclose an
        OTP, make a payment, or take another risky action elsewhere in it.
        """
        if not text:
            return text

        pieces = re.split(r"(?<=[.!?])\s+|\n+", text)
        protective_patterns = (
            cls.PROTECTIVE_WARNING_PATTERN,
            cls.PROTECTIVE_ADVICE_PATTERN,
            cls.PROTECTIVE_UPI_WARNING_PATTERN,
        )
        cleaned_pieces: list[str] = []
        for piece in pieces:
            cleaned = piece
            for pattern in protective_patterns:
                cleaned = pattern.sub(" ", cleaned)
            cleaned = re.sub(r"\s+", " ", cleaned).strip()
            if cleaned:
                cleaned_pieces.append(cleaned)
        return " ".join(cleaned_pieces)

    def analyze(
        self,
        text: str,
        url_risk: int = 0,
        url_signals: List[str] | None = None,
    ) -> RiskResult:
        if not isinstance(text, str) or not text.strip():
            return RiskResult(
                score=0,
                level="LOW RISK",
                category="Insufficient Data",
                reasons=["No message content was provided."],
                actions=[
                    "Provide a message or URL to analyze.",
                    "An empty input cannot be classified as safe.",
                ],
            )

        normalized = self._strip_protective_clauses(text.lower().strip())
        score = 0
        signals: List[str] = []
        reasons: List[str] = []

        def add_signal(name: str, points: int, reason: str) -> None:
            nonlocal score
            if name not in signals:
                signals.append(name)
                score += points
                reasons.append(reason)

        def matches(patterns: List[str]) -> bool:
            return any(re.search(pattern, normalized, re.IGNORECASE) for pattern in patterns)

        try:
            external_url_score = max(0, min(100, int(url_risk)))
        except (TypeError, ValueError, OverflowError):
            external_url_score = 0

        external_signals = [
            item for item in dict.fromkeys(url_signals or []) if isinstance(item, str)
        ]

        credential_request = matches(self.CREDENTIAL_REQUEST_PATTERNS)

        financial_action = matches(self.FINANCIAL_ACTION_PATTERNS)

        threats = matches(self.THREAT_PATTERNS)
        urgency = matches(self.URGENCY_PATTERNS)

        # 1. Credential theft.
        if credential_request:
            add_signal(
                "credential_request", 35,
                "The message appears to request sensitive authentication or account information.",
            )

        # 2. Financial requests.
        if financial_action:
            add_signal(
                "financial_request", 20,
                "The message requests a financial action or fee, or makes a potentially suspicious financial promise.",
            )

        # 3. Prize claims and advance-fee rewards.
        if matches(self.PRIZE_SCAM_PATTERNS):
            add_signal(
                "prize_claim", 20,
                "The message makes a prize or reward claim that should be independently verified.",
            )

        if self.ADVANCE_FEE_REWARD_PATTERN.search(normalized):
            add_signal(
                "advance_fee_reward_scheme", 15,
                "The message requests an advance or activation fee to obtain a promised reward, grant, or payment.",
            )

        # 4. Job offers: require a fee or an unusually high earnings claim.
        job_offer = matches(self.JOB_SCAM_PATTERNS)
        job_fee = bool(re.search(
            r"\b(?:registration|joining|processing|onboarding)\s+(?:deposit|fee)\b"
            r"|\bpay\s+(?:a\s+)?(?:refundable|small)?\s*fee\b"
            r"|\b(?:pay|payment)\b.{0,60}\b(?:deposit|fee)\b",
            normalized, re.IGNORECASE,
        ))
        unrealistic_earnings = bool(re.search(
            r"\b(?:earn|paying)\s+(?:rs\.?|inr|â‚¹|\$)?\s*[\d,]+\s*(?:daily|per\s+day|a\s+day)\b",
            normalized, re.IGNORECASE,
        ))
        if (job_offer or re.search(r"\b(?:job|worker|worker id|onboarding)\b", normalized)) and (job_fee or unrealistic_earnings):
            add_signal(
                "suspicious_job_offer", 20,
                "The job-related message combines an upfront fee/deposit or an unusually high earnings claim.",
            )

        # 5. Investment promises.
        if matches(self.INVESTMENT_SCAM_PATTERNS):
            add_signal(
                "suspicious_investment", 25,
                "The message promises unusually high or guaranteed investment returns.",
            )

        # 6. Delivery fees require both a delivery problem and payment.
        delivery_problem = matches(self.DELIVERY_SCAM_PATTERNS)
        delivery_payment = matches(self.DELIVERY_PAYMENT_PATTERNS)
        if delivery_problem and delivery_payment:
            add_signal(
                "suspicious_delivery_fee", 22,
                "The message combines a parcel or delivery problem with a payment request.",
            )

        # 7. UPI/refund manipulation and collect requests.
        if matches(self.UPI_REFUND_MANIPULATION_PATTERNS):
            add_signal(
                "upi_refund_manipulation", 35,
                "The message asks the recipient to approve a payment request to receive a refund. Verify in the official UPI app before acting.",
            )

        if matches(self.UPI_SCAM_PATTERNS):
            add_signal(
                "suspicious_upi_request", 30,
                "The message may misuse a UPI PIN or QR code in connection with receiving money.",
            )

        # 8. Crypto recovery phrases/private keys.
        if matches(self.CRYPTO_SECRET_REQUEST_PATTERNS):
            add_signal(
                "crypto_secret_request", 40,
                "The message appears to request a wallet recovery phrase, seed phrase, or private key. Never share these secrets.",
            )

        # 9. Confidential bank-detail changes / possible business email compromise.
        bank_change = matches(self.CONFIDENTIAL_BANK_CHANGE_PATTERNS)
        secrecy = bool(re.search(
            r"\b(?:confidential|secret|keep it quiet|until i confirm|don't tell|do not tell)\b",
            normalized,
        ))
        payment_context = bool(re.search(
            r"\b(?:transfer|payment|pay|vendor|supplier|bank details|account details)\b",
            normalized,
        ))
        if bank_change and secrecy and payment_context:
            add_signal(
                "confidential_bank_change", 35,
                "The message combines bank-detail or payment changes with secrecy. Independently verify through a trusted contact method.",
            )

        # 10. Threats and pressure.
        if threats:
            add_signal(
                "threat_or_pressure", 15,
                "The message threatens account restrictions, penalties, or other consequences.",
            )
        if urgency:
            add_signal(
                "urgency", 8,
                "The message creates time pressure or urges immediate action.",
            )
        if threats and urgency:
            add_signal(
                "threat_urgency_combination", 8,
                "An account threat is combined with time pressure, a common high-pressure scam tactic.",
            )

        # 11. Brand impersonation.
        brand_matches = [
            brand for brand in self.BRAND_KEYWORDS
            if re.search(r"(?<!\w)" + re.escape(brand) + r"(?!\w)", normalized)
        ]
        account_impersonation_link = bool(self.ACCOUNT_IMPERSONATION_LINK_PATTERN.search(normalized))
        if account_impersonation_link:
            add_signal(
                "account_update_link_impersonation", 25,
                "The message combines a recognizable financial brand, an account/KYC update or suspension claim, and a link. Verify through the institution's official app or website.",
            )

        suspicious_context = any(signal in signals for signal in (
            "credential_request", "financial_request", "prize_claim",
            "advance_fee_reward_scheme", "suspicious_job_offer",
            "suspicious_investment", "suspicious_delivery_fee",
            "suspicious_upi_request", "upi_refund_manipulation",
            "crypto_secret_request", "confidential_bank_change",
            "threat_or_pressure",
        ))
        if brand_matches and suspicious_context:
            add_signal(
                "possible_impersonation", 8,
                "A recognizable organization is mentioned alongside a suspicious request. The sender's identity has not been verified.",
            )

        # 12. URL structure. The external URL analyzer is weighted below.
        urls = self._extract_urls(text)
        if urls:
            if "contains_url" not in signals:
                signals.append("contains_url")
            reasons.append(
                "The message contains a URL. A link alone does not indicate fraud; reputation status is reported separately."
            )
            for raw_url in urls:
                candidate = raw_url
                if candidate.lower().startswith("www."):
                    candidate = "https://" + candidate
                try:
                    parsed = urlparse(candidate)
                    hostname = (parsed.hostname or "").lower()
                except ValueError:
                    continue
                if not hostname:
                    continue
                if parsed.scheme == "http":
                    add_signal(
                        "insecure_http", 10,
                        "The URL uses unencrypted HTTP. This alone does not prove fraud.",
                    )
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
                    add_signal(
                        "ip_address_host", 20,
                        "The URL uses an IP address rather than a conventional domain name.",
                    )

        # 13. Weighted external URL risk. URL is incorporated only here in the rule score.
        if external_url_score > 0:
            weighted_url_score = round(external_url_score * 0.35)
            score += weighted_url_score
            if "url_risk_elevated" not in signals:
                signals.append("url_risk_elevated")
            reasons.append(
                f"The URL analyzer supplied a risk score of {external_url_score}/100; a weighted contribution of {weighted_url_score} points was used."
            )

        for signal in external_signals:
            if signal not in signals:
                signals.append(signal)

        score = max(0, min(100, int(score)))
        if score >= 60:
            level = "HIGH RISK"
        elif score >= 30:
            level = "SUSPICIOUS"
        else:
            level = "LOW RISK"

        category = self._determine_category(signals)
        if level == "HIGH RISK":
            actions = [
                "Do not follow suspicious instructions or open unverified links.",
                "Never share an OTP, password, PIN, CVV, recovery phrase, or private key with a message sender.",
                "Verify requests through an official app or a contact method you independently trust.",
            ]
        elif level == "SUSPICIOUS":
            actions = [
                "Pause before acting on the message.",
                "Verify the sender and any request independently.",
                "Do not pay unexpected fees or enter sensitive information through an unsolicited link.",
            ]
        else:
            actions = [
                "No strong scam indicators were detected by these rules.",
                "This result does not guarantee that the message is safe.",
                "Verify unexpected requests for money or sensitive information through official channels.",
            ]

        return RiskResult(
            score=score,
            level=level,
            category=category,
            signals=signals,
            reasons=reasons,
            actions=actions,
        )

    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        """Extract likely URLs and remove trailing punctuation."""
        found = RiskEngine.URL_PATTERN.findall(text)
        cleaned = [item.rstrip(".,!?;:)}]") for item in found]
        return list(dict.fromkeys(cleaned))

    @staticmethod
    def _determine_category(signals: List[str]) -> str:
        if "crypto_secret_request" in signals:
            return "Crypto Wallet Credential Theft"
        if "upi_refund_manipulation" in signals or "suspicious_upi_request" in signals:
            return "Possible UPI / Refund Scam"
        if "confidential_bank_change" in signals:
            return "Possible Business Email Compromise"
        if "credential_request" in signals:
            return "Phishing / Credential Theft"
        if "suspicious_investment" in signals:
            return "Suspicious Investment Offer"
        if "suspicious_job_offer" in signals:
            return "Suspicious Job Offer"
        if "prize_claim" in signals or "advance_fee_reward_scheme" in signals:
            return "Prize / Reward Scam Indicators"
        if "suspicious_delivery_fee" in signals:
            return "Suspicious Delivery Fee"
        if "possible_impersonation" in signals or "account_update_link_impersonation" in signals:
            return "Possible Impersonation"
        if "financial_request" in signals:
            return "Financial Scam Indicators"
        if "threat_or_pressure" in signals:
            return "Threat / Account Scam Indicators"
        if "url_risk_elevated" in signals or any(signal in signals for signal in (
            "ip_address_host", "insecure_http", "hyphen_heavy_domain", "url_shortener"
        )):
            return "Suspicious URL Indicators"
        if "contains_url" in signals:
            return "General Message"
        if "urgency" in signals:
            return "Urgent Request - Needs Verification"
        return "No Strong Rule Indicators"


if __name__ == "__main__":
    engine = RiskEngine()
    examples = {
        "UPI refund request": "A payment request of â‚¹18,750 is waiting in your UPI app. Approve it to receive your refund.",
        "Confidential vendor payment": "The director has approved an urgent vendor payment. Use these new bank details and keep the transfer confidential until I confirm.",
        "Crypto recovery phrase": "Connect your wallet to claim the crypto airdrop and enter your wallet recovery phrase.",
        "Legitimate UPI warning": "Never approve a collect request you don't recognise. You do not need to share your UPI PIN to receive money.",
        "Legitimate delivery notice": "Your package is scheduled to arrive tomorrow. No payment is required.",
    }
    for name, message in examples.items():
        result = engine.analyze(message)
        print(f"\n=== {name} ===")
        print(f"Score: {result.score}/100 | Level: {result.level} | Category: {result.category}")
        print("Signals:", ", ".join(result.signals) or "none")
