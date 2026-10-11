"""Workflow state machine with explicit allowed transitions."""

from __future__ import annotations

from tprm.common.config import get_settings
from tprm.common.errors import InvalidTransition
from tprm.common.logging import get_logger
from tprm.workflow.models import WorkflowTransition

log = get_logger(__name__)


def _load_transitions() -> dict[str, list[str]]:
    """Load allowed transitions from workflow.yaml."""
    try:
        settings = get_settings()
        return settings.workflow.get("transitions", {})
    except Exception:
        # Fallback hardcoded transitions
        return {
            "Draft": ["InReview"],
            "InReview": ["RemediationRequested", "Escalated"],
            "RemediationRequested": ["RemediationInProgress", "Escalated"],
            "RemediationInProgress": ["Verified", "RemediationRequested"],
            "Verified": ["Accepted", "Rejected", "Escalated"],
            "Escalated": ["Accepted", "Rejected"],
            "Accepted": [],
            "Rejected": [],
        }


class WorkflowStateMachine:
    """Manages finding workflow state transitions.

    State is stored in an in-memory dict keyed by finding_id.
    Production would use the DB findings table.
    """

    def __init__(self) -> None:
        self._states: dict[str, str] = {}
        self._transitions: list[WorkflowTransition] = []
        self._allowed = _load_transitions()

    def get_status(self, finding_id: str) -> str:
        """Return current status for a finding (default: Draft)."""
        return self._states.get(finding_id, "Draft")

    def transition(
        self,
        finding_id: str,
        to_status: str,
        actor_id: str,
        reason: str = "",
    ) -> WorkflowTransition:
        """Transition a finding to a new status.

        Args:
            finding_id: The finding to transition.
            to_status: Target status.
            actor_id: User performing the transition.
            reason: Optional reason/comment.

        Returns:
            WorkflowTransition record.

        Raises:
            InvalidTransition: If the transition is not allowed.
        """
        from_status = self.get_status(finding_id)
        allowed_next = self._allowed.get(from_status, [])

        if to_status not in allowed_next:
            raise InvalidTransition(
                f"Transition from '{from_status}' to '{to_status}' is not allowed. "
                f"Allowed transitions: {allowed_next}"
            )

        # Idempotency: already in target state
        if from_status == to_status:
            existing = next(
                (t for t in reversed(self._transitions) if t.finding_id == finding_id),
                None,
            )
            if existing:
                return existing

        t = WorkflowTransition(
            finding_id=finding_id,
            from_status=from_status,
            to_status=to_status,
            actor_id=actor_id,
            reason=reason,
        )
        self._states[finding_id] = to_status
        self._transitions.append(t)

        log.info(
            "workflow_transition",
            finding_id=finding_id,
            from_status=from_status,
            to_status=to_status,
            actor_id=actor_id,
        )
        return t

    def history(self, finding_id: str) -> list[WorkflowTransition]:
        """Return all transitions for a finding."""
        return [t for t in self._transitions if t.finding_id == finding_id]
