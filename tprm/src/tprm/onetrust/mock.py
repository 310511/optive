"""MockOneTrustClient — default adapter, writes to local outbox."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from tprm.common.logging import get_logger
from tprm.onetrust.base import OneTrustClient

log = get_logger(__name__)


class MockOneTrustClient(OneTrustClient):
    """Default OneTrust adapter — writes payloads to an in-memory outbox.

    In production mode, the outbox would be the DB ``outbox`` table.
    For demo/testing, it stores to memory and optionally to a JSON file.
    """

    def __init__(self, outbox_path: Path | None = None) -> None:
        self._outbox: list[dict[str, Any]] = []
        self._outbox_path = outbox_path

    async def upsert_vendor(self, vendor_id: str, meta: dict[str, Any]) -> str:
        ot_id = f"mock-vendor-{vendor_id}"
        self._write_outbox("upsert_vendor", {"vendor_id": vendor_id, "ot_id": ot_id, **meta})
        return ot_id

    async def create_assessment(self, vendor_ot_id: str, meta: dict[str, Any]) -> str:
        ot_assessment_id = f"mock-assessment-{uuid.uuid4().hex[:8]}"
        self._write_outbox("create_assessment", {
            "vendor_ot_id": vendor_ot_id,
            "ot_assessment_id": ot_assessment_id,
            **meta,
        })
        return ot_assessment_id

    async def push_findings(self, assessment_ot_id: str, findings: list[dict[str, Any]]) -> None:
        # Validate: findings must not contain raw PII
        _validate_payload(findings)
        entry = {
            "assessment_ot_id": assessment_ot_id,
            "findings": findings,
            "pushed_at": datetime.utcnow().isoformat(),
        }
        self._write_outbox("push_findings", entry)
        log.info("mock_onetrust_findings_pushed", assessment_id=assessment_ot_id, count=len(findings))

    async def update_status(self, assessment_ot_id: str, status: str) -> None:
        self._write_outbox("update_status", {
            "assessment_ot_id": assessment_ot_id,
            "status": status,
            "updated_at": datetime.utcnow().isoformat(),
        })

    def _write_outbox(self, event_type: str, payload: dict[str, Any]) -> None:
        entry = {
            "id": str(uuid.uuid4()),
            "event_type": event_type,
            "payload": payload,
            "status": "sent",
            "created_at": datetime.utcnow().isoformat(),
        }
        self._outbox.append(entry)
        if self._outbox_path:
            with self._outbox_path.open("w") as f:
                json.dump(self._outbox, f, indent=2, default=str)

    def get_outbox(self) -> list[dict[str, Any]]:
        """Return the current outbox contents (for inspection/testing)."""
        return list(self._outbox)

    def clear_outbox(self) -> None:
        """Clear the outbox (for testing)."""
        self._outbox.clear()


def _validate_payload(findings: list[dict[str, Any]]) -> None:
    """Assert that no raw PII patterns appear in the findings payload.

    This is the final payload validator — a last-resort check before egress.
    """
    import re
    from tprm.common.errors import PayloadViolation

    # Check for raw email patterns (simplest common PII check)
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
    ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    cc_pattern = re.compile(r"\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b")

    payload_str = json.dumps(findings, default=str)
    for pattern, name in [(email_pattern, "EMAIL"), (ssn_pattern, "SSN"), (cc_pattern, "CREDIT_CARD")]:
        if pattern.search(payload_str):
            raise PayloadViolation(
                f"OneTrust outbox payload validator detected raw {name} in findings payload. "
                "Payload blocked."
            )
