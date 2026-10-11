"""Hash-chained, append-only audit log.

Each AuditEvent stores:
- ``prev_hash``: SHA-256 of the previous event's canonical content
- ``hash``: SHA-256 of this event's canonical content (including prev_hash)

This creates a tamper-evident chain: modifying any event invalidates all
subsequent hashes.

``counts`` fields store entity type counts only — never raw entity values.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tprm.common.logging import get_logger
from tprm.common.models import AuditEvent

log = get_logger(__name__)

# Genesis hash for the very first event in a chain
_GENESIS_HASH = "0" * 64


class AuditLog:
    """In-process append-only hash-chained audit log.

    For production use, events should be persisted to the ``audit_log`` DB table.
    This class provides the chain logic; persistence is the caller's responsibility.
    """

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = asyncio.Lock()

    @property
    def last_hash(self) -> str:
        """Return the hash of the most recent event, or the genesis hash."""
        if not self._events:
            return _GENESIS_HASH
        return self._events[-1].hash

    async def append(
        self,
        stage: str,
        doc_id: str,
        actor: str,
        action: str,
        counts: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append a new event to the chain and return it."""
        async with self._lock:
            event = AuditEvent(
                stage=stage,
                doc_id=doc_id,
                actor=actor,
                action=action,
                counts=counts or {},
                prev_hash=self.last_hash,
            )
            event.hash = event.compute_hash()
            self._events.append(event)
            log.info(
                "audit_event",
                stage=stage,
                doc_id=doc_id,
                action=action,
                counts=counts or {},
                hash=event.hash[:16] + "...",  # partial hash only
            )
            return event

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire chain.

        Returns True if valid; False if any event's hash is inconsistent.
        Logs a warning on the first detected violation.
        """
        prev_hash = _GENESIS_HASH
        for i, event in enumerate(self._events):
            # Recompute — use same method as when event was created
            recomputed = AuditEvent(
                ts=event.ts,
                stage=event.stage,
                doc_id=event.doc_id,
                actor=event.actor,
                action=event.action,
                counts=event.counts,
                prev_hash=prev_hash,
            ).compute_hash()

            if recomputed != event.hash:
                log.warning(
                    "audit_chain_violation",
                    event_index=i,
                    stage=event.stage,
                    doc_id=event.doc_id,
                )
                return False

            if event.prev_hash != prev_hash:
                log.warning(
                    "audit_prev_hash_mismatch",
                    event_index=i,
                    stage=event.stage,
                )
                return False

            prev_hash = event.hash

        return True

    def events_for_doc(self, doc_id: str) -> list[AuditEvent]:
        """Return all events for a given ``doc_id``."""
        return [e for e in self._events if e.doc_id == doc_id]

    def all_events(self) -> list[AuditEvent]:
        """Return a copy of all events (read-only)."""
        return list(self._events)


# ── Module-level singleton used by the orchestrator ───────────────────────────
# Individual pipeline stages should receive this via dependency injection.

_global_audit_log: AuditLog | None = None


def get_audit_log() -> AuditLog:
    """Return the module-level singleton AuditLog, creating it if needed."""
    global _global_audit_log  # noqa: PLW0603
    if _global_audit_log is None:
        _global_audit_log = AuditLog()
    return _global_audit_log


def reset_audit_log() -> None:
    """Reset the module-level singleton (for testing only)."""
    global _global_audit_log  # noqa: PLW0603
    _global_audit_log = None
