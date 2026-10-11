"""Workflow-specific data models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


AssessmentStatus = Literal[
    "Draft",
    "InReview",
    "RemediationRequested",
    "RemediationInProgress",
    "Verified",
    "Accepted",
    "Rejected",
    "Escalated",
]

TERMINAL_STATES: frozenset[str] = frozenset({"Accepted", "Rejected"})


class WorkflowTransition(BaseModel):
    """Record of a workflow state transition."""

    finding_id: str
    from_status: str
    to_status: str
    actor_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    reason: str = ""


class RemediationRecord(BaseModel):
    """Tracks vendor remediation response."""

    finding_id: str
    owner: str
    due_date: datetime
    vendor_response: str = ""
    evidence_links: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class EscalationRecord(BaseModel):
    """Escalation event."""

    finding_id: str
    reason: str
    escalated_to: str  # role: "risk_manager" | "ciso"
    escalated_at: datetime = Field(default_factory=datetime.utcnow)
    resolved: bool = False


class RiskAcceptance(BaseModel):
    """Risk acceptance record — requires expiry and justification."""

    finding_id: str
    accepted_by: str
    justification: str
    expiry_date: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)
