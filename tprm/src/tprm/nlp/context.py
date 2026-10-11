"""Context feature extraction for PII entities within blocks.

For each entity, computes:
- surrounding text window
- section heading
- table column header (for table_cell blocks)
- negation/example markers
"""

from __future__ import annotations

import re

from tprm.common.models import Block, Document, NLPContext, PIIEntity, SensitivityLevel
from tprm.common.config import get_settings

# Example/sample markers
_EXAMPLE_PATTERNS = re.compile(
    r"\b(?:e\.g\.|for example|sample|example|dummy|test|demo|fake|placeholder|redacted|fictional)\b",
    re.IGNORECASE,
)

# Negation markers
_NEGATION_PATTERNS = re.compile(
    r"\b(?:not|no|never|none|n/a|excluded|except|removed|deleted|anonymized|anonymised)\b",
    re.IGNORECASE,
)

_WINDOW_SIZE = 100  # chars on each side of the entity span


def build_context(
    block: Block,
    entities: list[PIIEntity],
    doc: Document,
) -> NLPContext:
    """Build NLP context features for a block.

    Returns an NLPContext with section/doc classification placeholders
    (filled in by classifier.py) and example/negation markers detected here.
    """
    settings = get_settings()
    policy = settings.policy

    text = block.text

    # Detect example/negation markers in the full block text
    is_example = bool(_EXAMPLE_PATTERNS.search(text))
    is_negated = bool(_NEGATION_PATTERNS.search(text))

    # Window context: join surrounding text around all entity spans
    windows: list[str] = []
    for entity in entities:
        start = max(0, entity.start - _WINDOW_SIZE)
        end = min(len(text), entity.end + _WINDOW_SIZE)
        window = text[start:end]
        # Scrub the entity text from the window for safe storage
        window = window[: entity.start - start] + "[ENTITY]" + window[entity.end - start :]
        windows.append(window)

    neighbors_ctx = " | ".join(windows[:3])  # cap at 3 windows for brevity

    # Section floor from policy config
    section_class = "unknown"  # will be updated by classifier
    doc_type = "unknown"
    floor_map = policy.get("section_floors", {})
    floor_str = floor_map.get(section_class, floor_map.get("default", "INTERNAL"))
    section_floor = SensitivityLevel.from_str(floor_str)

    return NLPContext(
        block_id=block.id,
        doc_type=doc_type,
        doc_type_confidence=0.0,
        section_class=section_class,
        section_class_confidence=0.0,
        relations=[],
        neighbors_ctx=neighbors_ctx,
        is_example=is_example,
        is_negated=is_negated,
        section_sensitivity_floor=section_floor,
        entity_canonical_ids={},
    )


def update_context_with_classification(
    ctx: NLPContext,
    doc_type: str,
    doc_type_confidence: float,
    section_class: str,
    section_class_confidence: float,
) -> NLPContext:
    """Return updated NLPContext with classifier results applied.

    Also recomputes the section_sensitivity_floor based on the assigned section_class.
    """
    settings = get_settings()
    policy = settings.policy

    floor_map = policy.get("section_floors", {})
    floor_str = floor_map.get(section_class, floor_map.get("default", "INTERNAL"))

    # Doc type can also impose a floor
    doc_floor_map = policy.get("doc_type_floors", {})
    doc_floor_str = doc_floor_map.get(doc_type, "INTERNAL")

    section_floor = SensitivityLevel.from_str(floor_str)
    doc_floor = SensitivityLevel.from_str(doc_floor_str)
    effective_floor = max(section_floor, doc_floor)

    return ctx.model_copy(
        update={
            "doc_type": doc_type,
            "doc_type_confidence": doc_type_confidence,
            "section_class": section_class,
            "section_class_confidence": section_class_confidence,
            "section_sensitivity_floor": effective_floor,
        }
    )
