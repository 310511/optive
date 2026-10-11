"""Control mapper: map risk category + section class to framework controls."""

from __future__ import annotations

from tprm.common.config import get_settings
from tprm.common.logging import get_logger
from tprm.common.models import ControlRef
from tprm.risk.extractor import NormalisedRisk

log = get_logger(__name__)


def map_controls(
    risk: NormalisedRisk,
    section_class: str,
    category: str,
) -> list[ControlRef]:
    """Map a risk to applicable framework controls with gap status.

    Args:
        risk: The normalised risk.
        section_class: The section class from NLP classification.
        category: Risk category ID.

    Returns:
        List of ControlRef with gap_status set based on evidence keywords.
    """
    settings = get_settings()
    controls_config = settings.controls
    all_controls = controls_config.get("controls", [])

    matched: list[ControlRef] = []
    risk_text = f"{risk.title} {risk.description}".lower()

    for ctl in all_controls:
        ctl_categories = ctl.get("categories", [])
        ctl_sections = ctl.get("section_classes", [])
        ctl_keywords = [kw.lower() for kw in ctl.get("keywords", [])]

        # Match by category or section class
        category_match = category in ctl_categories
        section_match = section_class in ctl_sections
        keyword_match = any(kw in risk_text for kw in ctl_keywords)

        if not (category_match or section_match or keyword_match):
            continue

        # Determine gap status from evidence keywords
        gap_status = _assess_gap_status(risk_text, ctl_keywords)

        matched.append(ControlRef(
            control_id=ctl["id"],
            framework=ctl["framework"],
            ref=ctl["ref"],
            name=ctl["name"],
            gap_status=gap_status,
        ))

    log.debug("controls_mapped", risk_id=risk.id, control_count=len(matched))
    return matched[:5]  # cap at 5 most relevant controls


def _assess_gap_status(risk_text: str, control_keywords: list[str]) -> str:
    """Heuristic: determine if the control is satisfied, partial, or missing."""
    # Positive evidence keywords suggest the control is implemented
    positive_terms = [
        "implemented", "enforced", "enabled", "configured", "deployed",
        "operational", "active", "in place", "compliant", "certified",
    ]
    negative_terms = [
        "not implemented", "missing", "lacking", "absent", "not configured",
        "gap", "deficiency", "exception", "finding", "failed", "no ",
    ]

    has_control_mention = any(kw in risk_text for kw in control_keywords)
    has_positive = any(t in risk_text for t in positive_terms)
    has_negative = any(t in risk_text for t in negative_terms)

    if has_negative:
        return "missing"
    if has_control_mention and has_positive:
        return "partial"
    return "missing"
