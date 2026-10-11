"""Escalation rules: Critical findings and SLA breaches."""

from __future__ import annotations

from datetime import datetime, timedelta

from tprm.common.config import get_settings
from tprm.common.logging import get_logger
from tprm.common.models import Finding
from tprm.workflow.models import EscalationRecord

log = get_logger(__name__)


def check_escalation(
    finding: Finding,
    state_machine: object,
) -> EscalationRecord | None:
    """Check if a finding requires escalation.

    Critical findings → CISO queue immediately.
    High findings past SLA → escalate.

    Returns an EscalationRecord if escalation is triggered, None otherwise.
    """
    from tprm.workflow.state_machine import WorkflowStateMachine

    if not isinstance(state_machine, WorkflowStateMachine):
        return None

    settings = get_settings()
    workflow_config = settings.workflow
    sla_days = workflow_config.get("sla_days", {})
    escalation_config = workflow_config.get("escalation", {})

    current_status = state_machine.get_status(finding.id)

    # Critical: escalate immediately on creation (move Draft → InReview → Escalated)
    if finding.severity == "Critical" and escalation_config.get("critical_immediate_escalation", True):
        if current_status in ("Draft", "InReview"):
            log.warning("escalation_critical", finding_id=finding.id)
            try:
                if current_status == "Draft":
                    state_machine.transition(finding.id, "InReview", "system", reason="Critical auto-escalation step 1")
                state_machine.transition(finding.id, "Escalated", "system", reason="Critical finding auto-escalation")
            except Exception:
                # If transition already done (idempotency), ignore
                pass
            return EscalationRecord(
                finding_id=finding.id,
                reason="Critical severity finding — immediate escalation",
                escalated_to=escalation_config.get("ciso_queue_role", "ciso"),
            )

    # High past SLA
    if finding.severity == "High" and escalation_config.get("high_past_sla_escalate", True):
        sla = sla_days.get("High", 30)
        due_date = finding.created_at + timedelta(days=sla)
        if datetime.utcnow() > due_date and current_status not in {"Accepted", "Rejected", "Escalated"}:
            log.warning("escalation_sla_breach", finding_id=finding.id, severity="High")
            state_machine.transition(finding.id, "Escalated", "system", reason="High finding past SLA")
            return EscalationRecord(
                finding_id=finding.id,
                reason=f"High finding unresolved past {sla}-day SLA",
                escalated_to="risk_manager",
            )

    return None
