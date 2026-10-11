"""Sensitivity level aggregation: per-block and per-document."""

from __future__ import annotations

from tprm.common.models import ClassifiedBlock, SensitivityLevel


def score_block(classified: ClassifiedBlock) -> ClassifiedBlock:
    """Compute and set block_level = max(decision levels, section floor).

    Returns updated ClassifiedBlock. Monotonic: never lowers level.
    """
    if not classified.decisions:
        floor = (
            classified.ctx.section_sensitivity_floor
            if classified.ctx
            else SensitivityLevel.INTERNAL
        )
        return classified.model_copy(update={"block_level": max(classified.block_level, floor)})

    max_decision = max(d.level for d in classified.decisions)
    floor = (
        classified.ctx.section_sensitivity_floor
        if classified.ctx
        else SensitivityLevel.INTERNAL
    )
    new_level = max(max_decision, floor, classified.block_level)
    return classified.model_copy(update={"block_level": new_level})


def score_document(classified_blocks: list[ClassifiedBlock]) -> SensitivityLevel:
    """Return the highest sensitivity level across all blocks."""
    if not classified_blocks:
        return SensitivityLevel.PUBLIC
    return max(b.block_level for b in classified_blocks)
