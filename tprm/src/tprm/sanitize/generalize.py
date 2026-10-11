"""Generalization: semantic downgrade of PII values.

Replaces specific values with category-level placeholders:
- IP address → [INTERNAL_IP_RANGE]
- Person name → [PERSON:<ROLE>]  (role from relation graph)
- Hostname → [HOST:<env>]
- Date → year-only
- Amount → magnitude bucket
"""

from __future__ import annotations

import re
from typing import Any

# IP range generalization
_IP_PRIVATE_RANGES = [
    re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}$"),
]

# Environment detection for hostnames
_ENV_PATTERNS = {
    "prod": re.compile(r"\b(?:prod|production|prd)\b", re.IGNORECASE),
    "staging": re.compile(r"\b(?:staging|stg|stage)\b", re.IGNORECASE),
    "dev": re.compile(r"\b(?:dev|develop|development)\b", re.IGNORECASE),
    "test": re.compile(r"\b(?:test|qa|uat)\b", re.IGNORECASE),
}

# Amount magnitude buckets
_AMOUNT_BUCKETS = [
    (1_000_000, "[$1M+]"),
    (100_000, "[$100K-$1M]"),
    (10_000, "[$10K-$100K]"),
    (1_000, "[$1K-$10K]"),
    (0, "[<$1K]"),
]

# Date generalization: extract year
_DATE_YEAR = re.compile(r"\b(19|20)\d{2}\b")

# Currency amounts
_AMOUNT_RE = re.compile(r"[\$£€¥]?\s*(\d{1,3}(?:[,\s]\d{3})*(?:\.\d{2})?)", re.IGNORECASE)


def generalize(
    text: str,
    spans: list[tuple[int, int, str, str]],
    relations: list[Any] | None = None,
) -> str:
    """Apply generalization to spans in text.

    Args:
        text: Original text.
        spans: List of (start, end, entity_type, raw_value) tuples.
        relations: Relation objects for role lookup (from NLP stage).

    Returns:
        Text with spans replaced by semantic placeholders.
    """
    sorted_spans = sorted(spans, key=lambda s: s[0], reverse=True)
    result = text

    for start, end, entity_type, raw_value in sorted_spans:
        placeholder = _generalize_value(entity_type, raw_value, relations or [])
        result = result[:start] + placeholder + result[end:]

    return result


def _generalize_value(
    entity_type: str,
    raw_value: str,
    relations: list[Any],
) -> str:
    """Return the generalized placeholder for a specific entity value."""
    match entity_type:
        case "IP_ADDRESS":
            return _generalize_ip(raw_value)
        case "INTERNAL_HOSTNAME":
            return _generalize_hostname(raw_value)
        case "PERSON":
            return _generalize_person(raw_value, relations)
        case "DATE_TIME" | "DATE_OF_BIRTH":
            return _generalize_date(raw_value)
        case _:
            # Generic generalization for unmapped types
            return f"[{entity_type}:GENERALIZED]"


def _generalize_ip(ip: str) -> str:
    """Replace IP with network range indicator."""
    stripped = ip.strip()
    for pattern in _IP_PRIVATE_RANGES:
        if pattern.match(stripped):
            return "[INTERNAL_IP_RANGE]"
    return "[EXTERNAL_IP]"


def _generalize_hostname(hostname: str) -> str:
    """Replace hostname with environment-tagged placeholder."""
    h = hostname.lower()
    for env, pattern in _ENV_PATTERNS.items():
        if pattern.search(h):
            return f"[HOST:{env}]"
    return "[HOST:internal]"


def _generalize_person(name: str, relations: list[Any]) -> str:
    """Replace person name with role-tagged placeholder using relation graph."""
    # Find role from relation graph
    for relation in relations:
        if (
            relation.relation_type == "person_role"
            and "role:" in relation.target_entity_id
        ):
            role = relation.target_entity_id.split("role:")[-1].upper()
            return f"[PERSON:{role}]"
    return "[PERSON:UNKNOWN]"


def _generalize_date(date_str: str) -> str:
    """Replace date with year only."""
    year_match = _DATE_YEAR.search(date_str)
    if year_match:
        return year_match.group(0)
    return "[DATE:YEAR]"
