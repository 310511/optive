"""REST API routes for TPRM pipeline."""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.security import APIKeyHeader

from tprm.common.audit import get_audit_log
from tprm.common.config import get_settings
from tprm.common.errors import (
    ApprovalViolation,
    GateViolation,
    InvalidTransition,
    UnsupportedFormat,
)
from tprm.common.models import AssessmentResult, Finding
from tprm.orchestrator import run_assessment
from tprm.workflow.state_machine import WorkflowStateMachine

router = APIRouter()
_state_machines: dict[str, WorkflowStateMachine] = {}
_assessments: dict[str, AssessmentResult] = {}

api_key_header = APIKeyHeader(name="X-API-Key")


def _verify_api_key(key: str = Depends(api_key_header)) -> str:
    settings = get_settings()
    if key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return key


@router.post("/assessments", response_model=dict[str, Any])
async def create_assessment(
    file: UploadFile = File(...),
    vendor_id: str = Form(...),
    _: str = Depends(_verify_api_key),
) -> dict[str, Any]:
    """Upload a vendor document and start an assessment."""
    suffix = Path(file.filename or "upload").suffix
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        result = await run_assessment(tmp_path, vendor_id=vendor_id, use_fake_llm=True)
        _assessments[result.assessment_id] = result
        _state_machines[result.assessment_id] = WorkflowStateMachine()
        return {
            "assessment_id": result.assessment_id,
            "doc_id": result.doc_id,
            "status": result.workflow_status,
            "sensitivity": result.document_sensitivity.name,
            "finding_count": len(result.findings),
        }
    except UnsupportedFormat as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except GateViolation as exc:
        raise HTTPException(status_code=422, detail=f"Gate violation: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)


@router.get("/assessments/{assessment_id}", response_model=dict[str, Any])
async def get_assessment(
    assessment_id: str,
    _: str = Depends(_verify_api_key),
) -> dict[str, Any]:
    """Get assessment status and summary."""
    result = _assessments.get(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {
        "assessment_id": result.assessment_id,
        "vendor_id": result.vendor_id,
        "filename": result.filename,
        "sensitivity": result.document_sensitivity.name,
        "workflow_status": result.workflow_status,
        "finding_count": len(result.findings),
        "stage_timings": result.stage_timings,
    }


@router.get("/assessments/{assessment_id}/findings", response_model=list[dict[str, Any]])
async def get_findings(
    assessment_id: str,
    _: str = Depends(_verify_api_key),
) -> list[dict[str, Any]]:
    """Get findings for an assessment."""
    result = _assessments.get(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return [
        {
            "id": f.id,
            "severity": f.severity,
            "score": f.score,
            "risk_category": f.risk_category,
            "title": f.title,
            "description": f.description,
            "section_label": f.section_label,
            "entity_types_found": f.entity_types_found,
            "recommendation": f.recommendation,
            "status": f.status,
            "controls": [c.model_dump() for c in f.controls],
        }
        for f in result.findings
    ]


@router.post("/assessments/{assessment_id}/transition", response_model=dict[str, Any])
async def transition_assessment(
    assessment_id: str,
    body: dict[str, Any],
    _: str = Depends(_verify_api_key),
) -> dict[str, Any]:
    """Transition assessment workflow state."""
    sm = _state_machines.get(assessment_id)
    if not sm:
        raise HTTPException(status_code=404, detail="Assessment not found")

    to_status = body.get("to_status", "")
    actor_id = body.get("actor_id", "api")
    reason = body.get("reason", "")

    # Use first finding as proxy for assessment-level state
    result = _assessments.get(assessment_id)
    finding_id = result.findings[0].id if result and result.findings else assessment_id

    try:
        t = sm.transition(finding_id, to_status, actor_id, reason=reason)
        return {"finding_id": t.finding_id, "from": t.from_status, "to": t.to_status}
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/audit/{doc_id}", response_model=list[dict[str, Any]])
async def get_audit_log_endpoint(
    doc_id: str,
    _: str = Depends(_verify_api_key),
) -> list[dict[str, Any]]:
    """Get audit log entries for a document."""
    audit = get_audit_log()
    events = audit.events_for_doc(doc_id)
    return [
        {
            "ts": e.ts.isoformat(),
            "stage": e.stage,
            "action": e.action,
            "counts": e.counts,
            "hash": e.hash[:16] + "...",
        }
        for e in events
    ]


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness check."""
    return {"status": "ok"}
