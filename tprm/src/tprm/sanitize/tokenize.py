"""Tokenization: replace PII spans with deterministic assessment-scoped tokens.

Token format: ``<<ENTITY_TYPE_xxxxxxxx>>`` where xxxxxxxx is 8 hex chars
derived from HMAC-SHA256(salt, entity_type:entity_text).

Properties:
- Deterministic within an assessment (same salt → same token)
- Non-deterministic across assessments (different salt → different token)
- Raw value never appears in output
"""

from __future__ import annotations

from tprm.common.crypto import derive_token


def tokenize(
    text: str,
    spans: list[tuple[int, int, str, str]],
    assessment_salt: str,
) -> tuple[str, dict[str, str]]:
    """Replace ``spans`` in ``text`` with deterministic tokens.

    Args:
        text: The original text.
        spans: List of (start, end, entity_type, raw_value) tuples.
        assessment_salt: Per-assessment HMAC salt.

    Returns:
        (tokenized_text, token_map) where token_map is {token: raw_value}.
        Raw values in the map should be stored in the vault by the caller.
    """
    # Sort right-to-left
    sorted_spans = sorted(spans, key=lambda s: s[0], reverse=True)

    result = text
    token_map: dict[str, str] = {}  # token → raw_value (for vault storage)

    for start, end, entity_type, raw_value in sorted_spans:
        token = derive_token(raw_value, entity_type, assessment_salt)
        token_map[token] = raw_value
        result = result[:start] + token + result[end:]

    return result, token_map
