"""Redaction: replace PII spans with typed placeholders.

Applies replacements right-to-left on character offsets to preserve
correctness when multiple spans overlap or are adjacent.

Idempotent: ``[REDACTED:TYPE]`` placeholders are not re-processed.
"""

from __future__ import annotations


def redact(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Replace ``spans`` in ``text`` with ``[REDACTED:<TYPE>]`` placeholders.

    Args:
        text: The original text.
        spans: List of (start, end, entity_type) tuples.

    Returns:
        Text with all spans replaced, processed right-to-left.
    """
    # Sort right-to-left so earlier offsets remain valid
    sorted_spans = sorted(spans, key=lambda s: s[0], reverse=True)

    result = text
    for start, end, entity_type in sorted_spans:
        placeholder = f"[REDACTED:{entity_type}]"
        result = result[:start] + placeholder + result[end:]

    return result


def is_already_redacted(text: str, entity_type: str) -> bool:
    """Return True if the text is already a redaction placeholder."""
    return text == f"[REDACTED:{entity_type}]"
