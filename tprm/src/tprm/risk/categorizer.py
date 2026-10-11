"""Risk categorizer: map NormalisedRisk to taxonomy categories."""

from __future__ import annotations

import re
from typing import Any

from tprm.common.config import get_settings
from tprm.common.logging import get_logger
from tprm.risk.extractor import NormalisedRisk

log = get_logger(__name__)


def categorize(risk: NormalisedRisk) -> str:
    """Map a risk to a taxonomy category ID.

    Uses keyword scoring + LLM claimed_category as a hint.
    The claimed_category is a hint only — deterministic rules decide.

    Returns:
        Category ID string (e.g. "ACCESS_MGMT", "ENCRYPTION").
    """
    settings = get_settings()
    taxonomy = settings.risk_taxonomy
    categories = taxonomy.get("categories", [])

    text = f"{risk.title} {risk.description}".lower()

    best_category = "INFO_SEC"
    best_score = 0

    for cat in categories:
        cat_id = cat["id"]
        keywords = [kw.lower() for kw in cat.get("keywords", [])]
        score = sum(1 for kw in keywords if kw in text)

        # Boost if LLM claimed this category
        if risk.claimed_category.upper() == cat_id:
            score += 2

        if score > best_score:
            best_score = score
            best_category = cat_id

    log.debug("risk_categorized", risk_id=risk.id, category=best_category, score=best_score)
    return best_category
