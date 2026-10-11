"""Unit tests for Workflow state machine, approval, and escalation."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

import pytest

os.environ.setdefault("TPRM_VAULT_KEY", "j5yCD74TW57pnqdPTzy_qHDrAjXX89hdQwdpM4Bf0l8=")
os.environ.setdefault("GATE_SIGNING_KEY", "test-gate-key")


def _make_finding(severity: str = "Medium", creator: str = "analyst1") -> object:
    from tprm.common.models import Finding
    return Finding(
        assessment_id="assess-1",
        vendor_id="vendor-1",
        risk_category="ACCESS_MGMT",
        severity=severity,  # type: ignore[arg-type]
        score=50,
        creator_id=creator,
        title="Test finding",
    )


class TestStateMachine:
    def test_valid_transition(self) -> None:
        from tprm.workflow.state_machine import WorkflowStateMachine

        sm = WorkflowStateMachine()
        finding_id = "f1"
        t = sm.transition(finding_id, "InReview", "analyst1")
        assert sm.get_status(finding_id) == "InReview"
        assert t.from_status == "Draft"
        assert t.to_status == "InReview"

    def test_invalid_transition_raises(self) -> None:
        from tprm.workflow.state_machine import WorkflowStateMachine
        from tprm.common.errors import InvalidTransition

        sm = WorkflowStateMachine()
        with pytest.raises(InvalidTransition):
            sm.transition("f1", "Accepted", "analyst1")  # Draft → Accepted not allowed

    def test_all_valid_paths_complete(self) -> None:
        from tprm.workflow.state_machine import WorkflowStateMachine

        sm = WorkflowStateMachine()
        fid = "f-path"
        sm.transition(fid, "InReview", "a1")
        sm.transition(fid, "RemediationRequested", "a1")
        sm.transition(fid, "RemediationInProgress", "vendor")
        sm.transition(fid, "Verified", "a1")
        sm.transition(fid, "Accepted", "manager")
        assert sm.get_status(fid) == "Accepted"

    def test_terminal_state_no_further_transitions(self) -> None:
        from tprm.workflow.state_machine import WorkflowStateMachine
        from tprm.common.errors import InvalidTransition

        sm = WorkflowStateMachine()
        fid = "f-terminal"
        # Fast path to Accepted via Escalated
        sm.transition(fid, "InReview", "a1")
        sm.transition(fid, "Escalated", "system")
        sm.transition(fid, "Accepted", "ciso")
        assert sm.get_status(fid) == "Accepted"

        # Should not be able to transition away from terminal state
        with pytest.raises(InvalidTransition):
            sm.transition(fid, "Draft", "a1")

    def test_idempotent_same_transition(self) -> None:
        from tprm.workflow.state_machine import WorkflowStateMachine

        sm = WorkflowStateMachine()
        sm.transition("f1", "InReview", "a1")
        # The machine is now at InReview; trying InReview again from InReview doesn't apply
        # InReview → InReview is not in allowed list, so it raises
        with pytest.raises(Exception):
            sm.transition("f1", "InReview", "a1")


class TestApproval:
    def test_approver_equals_creator_high_raises(self) -> None:
        from tprm.workflow.approval import approve
        from tprm.common.errors import ApprovalViolation
        from tprm.workflow.state_machine import WorkflowStateMachine

        finding = _make_finding(severity="High", creator="analyst1")
        sm = WorkflowStateMachine()
        sm._states[finding.id] = "Verified"  # type: ignore[union-attr]

        with pytest.raises(ApprovalViolation):
            approve(finding, approver_id="analyst1", decision="Accepted", state_machine=sm)  # type: ignore[arg-type]

    def test_different_approver_high_succeeds(self) -> None:
        from tprm.workflow.approval import approve
        from tprm.workflow.state_machine import WorkflowStateMachine

        finding = _make_finding(severity="High", creator="analyst1")
        sm = WorkflowStateMachine()
        sm._states[finding.id] = "Verified"  # type: ignore[union-attr]

        approve(finding, approver_id="manager1", decision="Accepted", state_machine=sm)  # type: ignore[arg-type]
        assert sm.get_status(finding.id) == "Accepted"  # type: ignore[union-attr]

    def test_low_severity_same_approver_ok(self) -> None:
        from tprm.workflow.approval import approve
        from tprm.workflow.state_machine import WorkflowStateMachine

        finding = _make_finding(severity="Low", creator="analyst1")
        sm = WorkflowStateMachine()
        sm._states[finding.id] = "Verified"  # type: ignore[union-attr]

        # No separation required for Low
        approve(finding, approver_id="analyst1", decision="Accepted", state_machine=sm)  # type: ignore[arg-type]
        assert sm.get_status(finding.id) == "Accepted"  # type: ignore[union-attr]

    def test_risk_acceptance_requires_expiry(self) -> None:
        from tprm.workflow.approval import create_risk_acceptance
        from tprm.common.errors import RiskAcceptanceError

        finding = _make_finding()
        with pytest.raises(RiskAcceptanceError, match="expiry"):
            create_risk_acceptance(finding, "manager", "A" * 50, expiry_date=None)  # type: ignore[arg-type]

    def test_risk_acceptance_requires_justification(self) -> None:
        from tprm.workflow.approval import create_risk_acceptance
        from tprm.common.errors import RiskAcceptanceError

        finding = _make_finding()
        expiry = datetime.utcnow() + timedelta(days=90)
        with pytest.raises(RiskAcceptanceError, match="justification"):
            create_risk_acceptance(finding, "manager", "too short", expiry_date=expiry)  # type: ignore[arg-type]

    def test_valid_risk_acceptance(self) -> None:
        from tprm.workflow.approval import create_risk_acceptance

        finding = _make_finding()
        expiry = datetime.utcnow() + timedelta(days=90)
        acceptance = create_risk_acceptance(
            finding, "manager",
            "This risk is accepted because the compensating control is in place.",
            expiry_date=expiry,
        )  # type: ignore[arg-type]
        assert acceptance.finding_id == finding.id  # type: ignore[union-attr]


class TestEscalation:
    def test_critical_finding_escalated_immediately(self) -> None:
        from tprm.workflow.escalation import check_escalation
        from tprm.workflow.state_machine import WorkflowStateMachine

        finding = _make_finding(severity="Critical")
        sm = WorkflowStateMachine()
        escalation = check_escalation(finding, sm)  # type: ignore[arg-type]
        assert escalation is not None
        assert sm.get_status(finding.id) == "Escalated"  # type: ignore[union-attr]
