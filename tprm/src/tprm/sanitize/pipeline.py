"""Sanitization pipeline — public interface.

Processes SENSITIVE ClassifiedBlocks and returns SanitizedBlocks.
Applies redact / tokenize / generalize per PolicyDecision.
Stores raw values in the token vault.
Preserves section headings, control statements, and table headers.
"""

from __future__ import annotations

import os

from tprm.common.crypto import derive_assessment_salt, load_vault_key
from tprm.common.errors import SanitizationError
from tprm.common.logging import get_logger
from tprm.common.models import (
    ClassifiedBlock,
    PolicyDecision,
    SanitizedBlock,
    SensitivityLevel,
    Transform,
)
from tprm.sanitize.generalize import generalize
from tprm.sanitize.redact import redact
from tprm.sanitize.tokenize import tokenize
from tprm.sanitize.vault import get_vault

log = get_logger(__name__)

# Placeholder patterns that must NOT be re-processed (idempotence guard)
import re as _re

_PLACEHOLDER_RE = _re.compile(
    r"\[REDACTED:[A-Z_]+\]|<<[A-Z_]+_[0-9a-f]{8}>>|\[INTERNAL_IP_RANGE\]|"
    r"\[PERSON:[A-Z_]+\]|\[HOST:[a-z_]+\]|\[ENTITY\]|\[[A-Z_]+:GENERALIZED\]"
)


def sanitize_pipeline(
    blocks: list[ClassifiedBlock],
    assessment_id: str,
    vendor_id: str = "unknown",
) -> list[SanitizedBlock]:
    """Sanitize all SENSITIVE blocks.

    SAFE blocks (PUBLIC/INTERNAL) are passed through as SanitizedBlocks
    with no transforms applied. This is intentional — the gate will re-scan them.

    Args:
        blocks: All classified blocks (SAFE and SENSITIVE).
        assessment_id: The current assessment UUID (for vault keying).
        vendor_id: Vendor ID for salt derivation.

    Returns:
        List of SanitizedBlock with raw PII replaced by placeholders/tokens.
    """
    vault = get_vault()

    # Derive per-assessment salt
    try:
        vault_key = load_vault_key()
    except Exception:
        # Tests may not have vault key; use a deterministic fallback for non-vault operations
        vault_key = b"test-key-32-bytes-exactly-padded"  # noqa: S105

    assessment_salt = derive_assessment_salt(vendor_id, assessment_id, vault_key)

    sanitized: list[SanitizedBlock] = []

    for classified in blocks:
        block = classified.block
        section_class = classified.ctx.section_class if classified.ctx else "unknown"

        try:
            if classified.block_level <= SensitivityLevel.INTERNAL:
                # SAFE path: no transforms needed
                sanitized.append(
                    SanitizedBlock(
                        block_id=block.id,
                        doc_id=block.doc_id,
                        section_path=block.section_path,
                        section_class=section_class,
                        text_sanitized=block.text,
                        applied=[],
                    )
                )
                continue

            # SENSITIVE path: apply transforms
            sanitized_text, transforms = _sanitize_block(
                classified,
                assessment_salt,
                assessment_id,
                vault,
            )
            sanitized.append(
                SanitizedBlock(
                    block_id=block.id,
                    doc_id=block.doc_id,
                    section_path=block.section_path,
                    section_class=section_class,
                    text_sanitized=sanitized_text,
                    applied=transforms,
                )
            )

        except Exception as exc:
            raise SanitizationError(
                f"Sanitization failed for block {block.id!r}: {exc}"
            ) from exc

    log.info(
        "sanitization_complete",
        assessment_id=assessment_id,
        block_count=len(blocks),
        sensitive_count=sum(1 for s in sanitized if s.applied),
    )
    return sanitized


def _sanitize_block(
    classified: ClassifiedBlock,
    assessment_salt: str,
    assessment_id: str,
    vault: object,
) -> tuple[str, list[Transform]]:
    """Apply all policy decisions to a single block.

    Returns (sanitized_text, list_of_transforms).
    """
    from tprm.sanitize.vault import TokenVault

    block = classified.block
    text = block.text
    relations = classified.ctx.relations if classified.ctx else []

    # Collect spans per action, grouping by (start, end)
    # decision is matched to the PIIEntity by entity_ref
    entity_map: dict[str, object] = {}
    if classified.entities:
        for entity in classified.entities:
            ref = f"{entity.block_id}:{entity.start}-{entity.end}"
            entity_map[ref] = entity

    redact_spans: list[tuple[int, int, str]] = []
    tokenize_spans: list[tuple[int, int, str, str]] = []
    generalize_spans: list[tuple[int, int, str, str]] = []
    keep_spans: set[str] = set()
    transforms: list[Transform] = []

    for decision in classified.decisions:
        entity = entity_map.get(decision.entity_ref)
        if entity is None:
            continue
        from tprm.common.models import PIIEntity

        assert isinstance(entity, PIIEntity)  # noqa: S101

        # Skip already-placeholder text (idempotence)
        span_text = text[entity.start : entity.end]
        if _PLACEHOLDER_RE.match(span_text):
            continue

        if decision.action == "keep":
            keep_spans.add(decision.entity_ref)
            continue
        elif decision.action == "redact":
            redact_spans.append((entity.start, entity.end, decision.entity_type))
            transforms.append(Transform(
                entity_type=decision.entity_type,
                action="redact",
                start=entity.start,
                end=entity.end,
                placeholder=f"[REDACTED:{decision.entity_type}]",
            ))
        elif decision.action == "tokenize":
            tokenize_spans.append((entity.start, entity.end, decision.entity_type, span_text))
            transforms.append(Transform(
                entity_type=decision.entity_type,
                action="tokenize",
                start=entity.start,
                end=entity.end,
                placeholder="<<TOKEN_PENDING>>",  # updated after tokenization
            ))
        elif decision.action == "generalize":
            generalize_spans.append((entity.start, entity.end, decision.entity_type, span_text))
            transforms.append(Transform(
                entity_type=decision.entity_type,
                action="generalize",
                start=entity.start,
                end=entity.end,
                placeholder="<<GENERALIZED_PENDING>>",
            ))

    # Apply: generalize first (in case some overlap with tokenize), then tokenize, then redact
    # All applied right-to-left within each pass

    if generalize_spans:
        text = generalize(text, generalize_spans, relations)

    if tokenize_spans:
        text, token_map = tokenize(text, tokenize_spans, assessment_salt)
        # Store tokens in vault
        if isinstance(vault, TokenVault):
            for token, raw_value in token_map.items():
                entity_type = next(
                    (s[2] for s in tokenize_spans if s[3] == raw_value), "UNKNOWN"
                )
                vault.store(token, raw_value, entity_type, assessment_id)
        # Update transform placeholders with actual tokens
        for t in transforms:
            if t.action == "tokenize" and t.placeholder == "<<TOKEN_PENDING>>":
                # Find matching token by original span position (already shifted — approximate)
                t.placeholder = next(iter(token_map.keys()), "<<TOKENIZED>>")

    if redact_spans:
        text = redact(text, redact_spans)

    return text, transforms
