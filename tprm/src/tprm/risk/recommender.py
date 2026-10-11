"""Recommender: generate remediation recommendations for findings."""

from __future__ import annotations

from tprm.common.logging import get_logger
from tprm.common.models import ControlRef, Finding

log = get_logger(__name__)

# Template library keyed by (category, control_ref)
_TEMPLATES: dict[str, str] = {
    "ACCESS_MGMT": (
        "Implement mandatory multi-factor authentication (MFA) for all user accounts, "
        "especially privileged accounts. Review and enforce least-privilege access principles. "
        "Conduct quarterly access reviews and promptly revoke access upon role changes."
    ),
    "ENCRYPTION": (
        "Ensure all data at rest is encrypted using AES-256 or stronger. "
        "Enforce TLS 1.2+ (preferably TLS 1.3) for all data in transit. "
        "Implement a formal key management process with regular key rotation."
    ),
    "INCIDENT_RESPONSE": (
        "Develop and test a documented incident response plan. "
        "Establish a security incident response team (CSIRT) with defined roles. "
        "Implement breach notification procedures compliant with applicable regulations (e.g., 72-hour GDPR notification)."
    ),
    "BC_DR": (
        "Develop and regularly test business continuity and disaster recovery plans. "
        "Define and document Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO). "
        "Ensure backups are tested, encrypted, and stored off-site."
    ),
    "PRIVACY_DATA": (
        "Review data processing activities against privacy regulations (GDPR, CCPA). "
        "Implement data minimisation principles and enforce retention policies. "
        "Ensure data subject rights requests (access, deletion) can be fulfilled within required timeframes."
    ),
    "COMPLIANCE_AUDIT": (
        "Address all audit findings and exceptions identified in the most recent assessment. "
        "Implement a remediation tracking process with defined SLAs for finding closure. "
        "Schedule a follow-up assessment to verify remediation effectiveness."
    ),
    "SUBPROCESSOR": (
        "Conduct formal due diligence on all subprocessors and fourth-party vendors. "
        "Ensure data processing agreements (DPAs) are in place with all subprocessors. "
        "Implement a subprocessor change notification process."
    ),
    "INFO_SEC": (
        "Conduct a comprehensive security assessment to identify and remediate vulnerabilities. "
        "Implement a vulnerability management program with defined patching SLAs. "
        "Ensure security controls are regularly tested and validated."
    ),
    "AI_MODEL_RISK": (
        "Establish an AI governance framework with defined policies for model use. "
        "Implement model risk management processes including validation and monitoring. "
        "Ensure transparency and explainability requirements are documented."
    ),
    "FINANCIAL": (
        "Verify adequate cyber insurance coverage is maintained. "
        "Review contract terms for liability caps and indemnification clauses. "
        "Assess financial viability and business continuity risk."
    ),
    "OPERATIONAL_RESILIENCE": (
        "Review and strengthen SLA commitments and penalties for availability breaches. "
        "Implement redundancy and failover capabilities for critical services. "
        "Conduct regular operational resilience testing (tabletop exercises, failover drills)."
    ),
}


def recommend(finding: Finding) -> str:
    """Generate a remediation recommendation for a finding.

    Uses the template library keyed by risk_category.
    Returns deterministic text — LLM polishing is explicitly not used here
    to keep the recommendation path fully deterministic and auditable.

    Args:
        finding: The Finding to generate a recommendation for.

    Returns:
        Remediation recommendation string.
    """
    template = _TEMPLATES.get(finding.risk_category, _TEMPLATES["INFO_SEC"])

    # Append control-specific guidance if controls are mapped
    control_guidance = _build_control_guidance(finding.controls)

    recommendation = template
    if control_guidance:
        recommendation += f"\n\nRelevant framework controls: {control_guidance}"

    log.debug("recommendation_generated", finding_id=finding.id, category=finding.risk_category)
    return recommendation


def _build_control_guidance(controls: list[ControlRef]) -> str:
    """Build a compact control reference string for the recommendation."""
    if not controls:
        return ""
    refs = [f"{c.framework} {c.ref} ({c.name})" for c in controls[:3]]
    return "; ".join(refs)
