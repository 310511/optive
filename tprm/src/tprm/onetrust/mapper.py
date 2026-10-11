"""Field mapper: Finding → OneTrust payload.

All field mappings are configured in config/onetrust_mapping.yaml (not hardcoded).
"""

from __future__ import annotations

import uuid
from typing import Any

from tprm.common.models import Finding


def map_finding_to_onetrust(
    finding: Finding,
    mapping: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Map a Finding to an OneTrust-compatible dict.

    Args:
        finding: The finding to map.
        mapping: Optional field mapping from config. If None, uses defaults.

    Returns:
        Dict suitable for OneTrust API payload.
        Contains ONLY sanitized fields — no raw PII.
    """
    if mapping is None:
        mapping = _default_mapping()

    payload: dict[str, Any] = {}

    # Map each field according to the mapping config
    field_map = mapping.get("finding_fields", {})
    for our_field, ot_field in field_map.items():
        value = getattr(finding, our_field, None)
        if value is not None:
            payload[ot_field] = value

    # Always include idempotency key
    payload["idempotencyKey"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, finding.id))
    payload["sourceSystem"] = "TPRM-Pipeline"

    return payload


def _default_mapping() -> dict[str, Any]:
    """Default field mapping (used when config YAML not present)."""
    return {
        "finding_fields": {
            "id": "externalId",
            "risk_category": "riskCategory",
            "severity": "riskLevel",
            "score": "riskScore",
            "recommendation": "remediationGuidance",
            "status": "status",
            "title": "name",
            "description": "description",
        }
    }
