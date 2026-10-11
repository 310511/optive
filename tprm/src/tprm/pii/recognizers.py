"""Custom Presidio recognizers for TPRM-specific PII types.

Each recognizer is a PatternRecognizer subclass with:
- patterns: regex + score
- context: context words that boost score
- Optional validation (Luhn, IBAN modulo-97)
"""

from __future__ import annotations

import math
import re
from typing import Any

from presidio_analyzer import PatternRecognizer  # type: ignore[import-untyped]
from presidio_analyzer.pattern_recognizer import Pattern  # type: ignore[import-untyped]


# ── Luhn validation ──────────────────────────────────────────────────────────

def _luhn_valid(number: str) -> bool:
    """Return True if the digit string passes the Luhn check."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_valid(iban: str) -> bool:
    """Return True if IBAN passes the ISO 13616 modulo-97 check."""
    cleaned = re.sub(r"\s", "", iban).upper()
    if len(cleaned) < 15:
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord("A") + 10)
        else:
            return False
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)


# ── Custom recognizer classes ─────────────────────────────────────────────────


class IBANRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern(
            "IBAN",
            r"[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[0-9]{2})?",
            0.5,
        )
    ]
    CONTEXT = ["iban", "bank account", "account number", "bic", "swift"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="IBAN_CODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )

    def validate_result(self, pattern_text: str) -> bool | None:  # type: ignore[override]
        return _iban_valid(pattern_text.strip())


class CreditCardRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern(
            "CREDIT_CARD_SPACED",
            r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
            0.6,
        ),
        Pattern(
            "CREDIT_CARD_13",
            r"\b\d{13}\b",
            0.3,
        ),
    ]
    CONTEXT = [
        "credit card", "card number", "visa", "mastercard", "amex",
        "payment", "invoice", "billing",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="CREDIT_CARD",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )

    def validate_result(self, pattern_text: str) -> bool | None:  # type: ignore[override]
        return _luhn_valid(pattern_text)


class MacAddressRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern(
            "MAC_COLON",
            r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b",
            0.7,
        ),
        Pattern(
            "MAC_HYPHEN",
            r"\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b",
            0.7,
        ),
    ]
    CONTEXT = ["mac address", "hardware address", "network interface", "device"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="MAC_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class CredentialURLRecognizer(PatternRecognizer):
    """Detects URLs with embedded credentials (user:pass@host)."""
    PATTERNS = [
        Pattern(
            "CRED_URL",
            r"[a-zA-Z][a-zA-Z0-9+\-.]*://[A-Za-z0-9._~%-]+:[A-Za-z0-9._~%-]+@[A-Za-z0-9.\-]+",
            0.9,
        ),
    ]
    CONTEXT = ["connection string", "database url", "dsn", "credentials", "password"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="CREDENTIAL_URL",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class APIKeyRecognizer(PatternRecognizer):
    """Detects API keys and secrets by provider prefixes and high entropy."""
    PATTERNS = [
        Pattern("AWS_KEY", r"\bAKIA[0-9A-Z]{16}\b", 0.9),
        Pattern("GITHUB_TOKEN", r"\bghp_[A-Za-z0-9]{36}\b", 0.95),
        Pattern("SLACK_TOKEN", r"\bxoxb-[A-Za-z0-9\-]{24,}\b", 0.95),
        Pattern("GITHUB_OAUTH", r"\bgho_[A-Za-z0-9]{36}\b", 0.9),
        Pattern("STRIPE_KEY", r"\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b", 0.95),
        # Generic high-entropy alphanumeric (32+ chars)
        Pattern("GENERIC_SECRET", r"\b[A-Za-z0-9+/]{32,}\b", 0.3),
    ]
    CONTEXT = [
        "api key", "secret key", "access key", "token", "credential",
        "aws", "github", "slack", "stripe",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="API_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )

    def validate_result(self, pattern_text: str) -> bool | None:  # type: ignore[override]
        # For the generic pattern, require high entropy
        if not any(pattern_text.startswith(prefix) for prefix in ["AKIA", "ghp_", "xoxb-", "gho_", "sk_"]):
            return _shannon_entropy(pattern_text) > 4.5
        return True


class PEMPrivateKeyRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern(
            "PEM_HEADER",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            0.95,
        ),
    ]
    CONTEXT = ["private key", "certificate", "pem", "key material", "signing key"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="PEM_PRIVATE_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class InternalHostnameRecognizer(PatternRecognizer):
    """Detects internal hostnames/domains from configured org domains."""
    PATTERNS = [
        # Matches hostnames with at least one dot (e.g., db-primary.corp.acme.internal)
        Pattern(
            "INTERNAL_HOST",
            r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:internal|corp|intra|local|lan)\b",
            0.7,
        ),
    ]
    CONTEXT = [
        "host", "hostname", "server", "endpoint", "infrastructure",
        "database", "service", "internal network",
    ]

    def __init__(self, org_domains: list[str] | None = None) -> None:
        # Build additional patterns from org domains if provided
        extra_patterns = []
        if org_domains:
            for domain in org_domains:
                escaped = re.escape(domain)
                extra_patterns.append(
                    Pattern(f"ORG_DOMAIN_{domain}", rf"\b[a-z0-9\-]+\.{escaped}\b", 0.8)
                )
        super().__init__(
            supported_entity="INTERNAL_HOSTNAME",
            patterns=self.PATTERNS + extra_patterns,
            context=self.CONTEXT,
        )


class EmployeeIDRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern("EMP_ID", r"\bEMP-\d{4,8}\b", 0.7),
        Pattern("EMP_ID2", r"\b(?:employee|emp)\s*(?:id|#|no\.?)\s*:?\s*[A-Z0-9]{4,10}\b", 0.6),
    ]
    CONTEXT = ["employee", "staff", "personnel", "hr", "payroll"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="EMPLOYEE_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class ContractNumberRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern("CONTRACT_NO", r"\bCONT-[A-Z0-9]{6,12}\b", 0.7),
        Pattern("PO_NO", r"\bPO-\d{5,10}\b", 0.7),
        Pattern("CONTRACT_GENERIC", r"\b(?:contract|agreement|PO)\s*(?:no\.?|number|#)\s*:?\s*[A-Z0-9\-]{4,15}\b", 0.5),
    ]
    CONTEXT = ["contract", "agreement", "purchase order", "PO", "invoice"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="CONTRACT_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class BankAccountRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern("BANK_ACCT", r"\b\d{8,12}\b", 0.3),
        Pattern("ROUTING_ACCT", r"\b\d{9}\s+\d{8,12}\b", 0.6),
    ]
    CONTEXT = [
        "bank account", "account number", "routing number",
        "aba", "sort code", "bsb", "payment",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="BANK_ACCOUNT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


def build_custom_recognizers(org_domains: list[str] | None = None) -> list[PatternRecognizer]:
    """Return all custom recognizer instances for registration with Presidio."""
    return [
        IBANRecognizer(),
        CreditCardRecognizer(),
        MacAddressRecognizer(),
        CredentialURLRecognizer(),
        APIKeyRecognizer(),
        PEMPrivateKeyRecognizer(),
        InternalHostnameRecognizer(org_domains=org_domains),
        EmployeeIDRecognizer(),
        ContractNumberRecognizer(),
        BankAccountRecognizer(),
    ]
