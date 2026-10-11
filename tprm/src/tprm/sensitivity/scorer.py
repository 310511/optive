"""Route classified blocks to SAFE or SENSITIVE path."""

from __future__ import annotations

from typing import Literal

from tprm.common.models import ClassifiedBlock, SensitivityLevel


def route(classified: ClassifiedBlock) -> Literal["SAFE", "SENSITIVE"]:
    """Route a classified block.

    - PUBLIC or INTERNAL → 'SAFE' (direct to gate)
    - CONFIDENTIAL or RESTRICTED → 'SENSITIVE' (through sanitization)
    - Any error or unknown → 'SENSITIVE' (fail closed)
    """
    try:
        if classified.block_level <= SensitivityLevel.INTERNAL:
            return "SAFE"
        return "SENSITIVE"
    except Exception:
        # Fail closed: any error in routing → SENSITIVE
        return "SENSITIVE"
