"""Approval logic: role-based with creator/approver separation for High/Critical."""

from __future__ import annotations

from tprm.common.errors import ApprovalViolation, RiskAcceptanceError
from tprm.common.logging import get_logger
from tprm.common.models import Finding
from tprm.workflow.models import RiskAcceptance

log = get_logger(__name__)

_SEPARATION_REQUIRED = {"High", "Critical"}


def approve(
    finding: Finding,
    approver_id: str,
    decision: str,
    reason: str = "",
    state_machine: object = None,
) -> None:
    """Approve or reject a finding.

    Args:
        finding: The finding to approve.
        approver_id: ID of the approver.
        decision: "Accepted" or "Rejected"
        reason: Optional reason.
        state_machine: WorkflowStateMachine instance.

    Raises:
        ApprovalViolation: If approver == creator for High/Critical.
        InvalidTransition: If the current state doesn't allow approval.
    """
    if finding.severity in _SEPARATION_REQUIRED:
        if approver_id == finding.creator_id:
            raise ApprovalViolation(
                f"Finding {finding.id!r} is {finding.severity} severity. "
                "The approver must be different from the creator."
            )

    if state_machine is not None:
        from tprm.workflow.state_machine import WorkflowStateMachine

        if isinstance(state_machine, WorkflowStateMachine):
            state_machine.transition(finding.id, decision, approver_id, reason=reason)

    log.info(
        "finding_approved",
        finding_id=finding.id,
        decision=decision,
        approver_id=approver_id,
    )


def create_risk_acceptance(
    finding: Finding,
    accepted_by: str,
    justification: str,
    expiry_date: object,
) -> RiskAcceptance:
    """Create a risk acceptance record.

    Raises:
        RiskAcceptanceError: If expiry_date is missing or justification is too short.
    """
    from datetime import datetime

    if expiry_date is None:
        raise RiskAcceptanceError("Risk acceptance requires an expiry date.")

    if not justification or len(justification.strip()) < 50:
        raise RiskAcceptanceError(
            "Risk acceptance requires a justification of at least 50 characters."
        )

    if isinstance(expiry_date, str):
        expiry_date = datetime.fromisoformat(expiry_date)

    return RiskAcceptance(
        finding_id=finding.id,
        accepted_by=accepted_by,
        justification=justification.strip(),
        expiry_date=expiry_date,  # type: ignore[arg-type]
    )
