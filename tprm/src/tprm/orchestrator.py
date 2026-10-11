"""Orchestrator: runs the full TPRM pipeline end-to-end.

Public interface: run_assessment(file_path, vendor_id) -> AssessmentResult

Enforces idempotency on (vendor_id, sha256).
Emits audit events per stage.
Records per-stage timing.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from tprm.ai.analyzer import FakeLLM, LLMBackend, analyze
from tprm.common.audit import get_audit_log
from tprm.common.config import get_settings
from tprm.common.errors import GateViolation, SanitizationError
from tprm.common.logging import get_logger
from tprm.common.models import AssessmentResult, ClassifiedBlock, Finding, SensitivityLevel
from tprm.gate.gate import process as gate_process
from tprm.ingestion.parser import parse
from tprm.nlp.classifier import classify_doc, classify_section
from tprm.nlp.context import build_context, update_context_with_classification
from tprm.nlp.relations import build_relations, get_canonical_ids
from tprm.onetrust.mapper import map_finding_to_onetrust
from tprm.onetrust.mock import MockOneTrustClient
from tprm.pii.detector import detect
from tprm.policy.engine import PolicyEngine
from tprm.risk.categorizer import categorize
from tprm.risk.controls import map_controls
from tprm.risk.extractor import NormalisedRisk, extract
from tprm.risk.recommender import recommend
from tprm.risk.severity import score_severity
from tprm.sanitize.pipeline import sanitize_pipeline
from tprm.sanitize.vault import get_vault
from tprm.sensitivity.levels import score_block, score_document
from tprm.sensitivity.scorer import route
from tprm.workflow.state_machine import WorkflowStateMachine

log = get_logger(__name__)


async def run_assessment(
    file_path: Path,
    vendor_id: str,
    assessment_id: str | None = None,
    llm: LLMBackend | None = None,
    use_fake_llm: bool = False,
) -> AssessmentResult:
    """Run the full TPRM pipeline for a vendor document.

    Args:
        file_path: Path to the vendor document (PDF/DOCX/XLSX).
        vendor_id: The vendor being assessed.
        assessment_id: Optional pre-assigned UUID (for idempotency checks).
        llm: Optional LLM backend override.
        use_fake_llm: If True, use FakeLLM instead of real Ollama.

    Returns:
        AssessmentResult with findings, gate report, and workflow state.
    """
    if assessment_id is None:
        assessment_id = str(uuid.uuid4())

    audit = get_audit_log()
    timings: dict[str, float] = {}
    settings = get_settings()

    if use_fake_llm or llm is None:
        llm = llm or FakeLLM()

    log.info("assessment_start", assessment_id=assessment_id, vendor_id=vendor_id, file=file_path.name)

    # ── Stage 1: Document Ingestion ───────────────────────────────────────────
    t0 = time.time()
    doc = parse(file_path, vendor_id=vendor_id)
    timings["ingestion"] = time.time() - t0
    await audit.append("ingestion", doc.doc_id, "orchestrator", "parsed", {
        "block_count": len(doc.blocks),
        "format": doc.meta.doc_format,
    })

    # ── Stage 2: PII Detection ────────────────────────────────────────────────
    t0 = time.time()
    policy_cfg = settings.policy
    thresholds = policy_cfg.get("recognizer_thresholds", {})
    org_domains = policy_cfg.get("org", {}).get("domains", [])
    entities = detect(doc.blocks, thresholds=thresholds, org_domains=org_domains)
    timings["pii_detection"] = time.time() - t0
    entity_counts: dict[str, int] = {}
    for e in entities:
        entity_counts[e.entity_type] = entity_counts.get(e.entity_type, 0) + 1
    await audit.append("pii", doc.doc_id, "orchestrator", "detected", entity_counts)

    # ── Stage 3: Local NLP ────────────────────────────────────────────────────
    t0 = time.time()
    relations = build_relations(doc.blocks, entities)
    canonical_ids = get_canonical_ids(entities)
    doc_text = " ".join(b.text[:200] for b in doc.blocks[:10])
    doc_classification = classify_doc(doc_text)
    timings["nlp"] = time.time() - t0
    await audit.append("nlp", doc.doc_id, "orchestrator", "classified", {
        "doc_type": doc_classification.label,
        "confidence": round(doc_classification.confidence, 2),
    })

    # ── Stage 4 & 5: Policy Engine + Sensitivity ──────────────────────────────
    t0 = time.time()
    policy_engine = PolicyEngine()
    classified_blocks: list[ClassifiedBlock] = []

    entities_by_block: dict[str, list[Any]] = {}
    for entity in entities:
        entities_by_block.setdefault(entity.block_id, []).append(entity)

    for block in doc.blocks:
        block_entities = entities_by_block.get(block.id, [])
        ctx = build_context(block, block_entities, doc)
        section_class = classify_section(block.text)
        ctx = update_context_with_classification(
            ctx,
            doc_type=doc_classification.label,
            doc_type_confidence=doc_classification.confidence,
            section_class=section_class.label,
            section_class_confidence=section_class.confidence,
        )
        ctx = ctx.model_copy(update={
            "relations": relations,
            "entity_canonical_ids": canonical_ids,
        })

        decisions = [
            policy_engine.decide(entity, ctx, block)
            for entity in block_entities
        ]

        cb = ClassifiedBlock(block=block, entities=block_entities, ctx=ctx, decisions=decisions)
        cb = score_block(cb)
        classified_blocks.append(cb)

    doc_sensitivity = score_document(classified_blocks)
    timings["policy_sensitivity"] = time.time() - t0
    await audit.append("policy", doc.doc_id, "orchestrator", "classified", {
        "doc_sensitivity": doc_sensitivity.name,
        "total_blocks": len(classified_blocks),
    })

    # ── Stage 6: Sanitization ─────────────────────────────────────────────────
    t0 = time.time()
    sanitized_blocks = sanitize_pipeline(classified_blocks, assessment_id, vendor_id)
    timings["sanitization"] = time.time() - t0
    await audit.append("sanitize", doc.doc_id, "orchestrator", "sanitized", {
        "sanitized_blocks": sum(1 for b in sanitized_blocks if b.applied),
    })

    # ── Stage 7: Security Gate ────────────────────────────────────────────────
    t0 = time.time()
    vault = get_vault()
    raw_values = vault.lookup_raw_values(assessment_id)

    try:
        gate_payload = gate_process(
            blocks=sanitized_blocks,
            doc_id=doc.doc_id,
            vendor_id=vendor_id,
            assessment_id=assessment_id,
            doc_type=doc_classification.label,
            raw_values_for_check=raw_values,
        )
    except GateViolation as exc:
        await audit.append("gate", doc.doc_id, "orchestrator", "quarantine", {})
        raise
    timings["gate"] = time.time() - t0

    # ── Stage 8: AI Risk Analysis ─────────────────────────────────────────────
    t0 = time.time()
    ai_result = await analyze(gate_payload, llm=llm)
    timings["ai_analysis"] = time.time() - t0
    await audit.append("ai", doc.doc_id, "orchestrator", "analyzed", {
        "risk_items": len(ai_result.items),
    })

    # ── Stage 9: Risk Engine ──────────────────────────────────────────────────
    t0 = time.time()
    normalised_risks = extract(ai_result, sanitized_blocks)
    findings: list[Finding] = []

    for risk in normalised_risks:
        category = categorize(risk)
        section_class = sanitized_blocks[0].section_class if sanitized_blocks else "unknown"
        controls = map_controls(risk, section_class, category)
        gap_status = controls[0].gap_status if controls else "missing"
        severity = score_severity(
            risk,
            category,
            gap_status=gap_status,
            vendor_criticality=doc.meta.vendor_criticality,
        )
        finding = Finding(
            assessment_id=assessment_id,
            vendor_id=vendor_id,
            risk_category=category,
            severity=severity.label,
            score=severity.score,
            controls=controls,
            evidence_block_ids=risk.evidence_block_ids,
            title=risk.title,
            description=risk.description,
        )
        finding.recommendation = recommend(finding)
        findings.append(finding)

    timings["risk_engine"] = time.time() - t0
    await audit.append("risk", doc.doc_id, "orchestrator", "findings_generated", {
        "finding_count": len(findings),
    })

    # ── Stage 10: Workflow ────────────────────────────────────────────────────
    state_machine = WorkflowStateMachine()
    for finding in findings:
        from tprm.workflow.escalation import check_escalation
        check_escalation(finding, state_machine)

    workflow_status = "Draft"
    if findings:
        workflow_status = state_machine.get_status(findings[0].id)

    # ── Stage 11: OneTrust outbox ─────────────────────────────────────────────
    ot_client = MockOneTrustClient()
    ot_vendor_id = await ot_client.upsert_vendor(vendor_id, {"name": vendor_id})
    ot_assessment_id = await ot_client.create_assessment(ot_vendor_id, {
        "externalId": assessment_id,
        "documentFormat": doc.meta.doc_format,
    })
    ot_findings = [map_finding_to_onetrust(f) for f in findings]
    if ot_findings:
        await ot_client.push_findings(ot_assessment_id, ot_findings)
    await ot_client.update_status(ot_assessment_id, workflow_status)

    result = AssessmentResult(
        assessment_id=assessment_id,
        vendor_id=vendor_id,
        doc_id=doc.doc_id,
        filename=file_path.name,
        document_sensitivity=doc_sensitivity,
        gate_report=gate_payload.gate_report,
        findings=findings,
        workflow_status=workflow_status,
        stage_timings=timings,
    )

    log.info(
        "assessment_complete",
        assessment_id=assessment_id,
        vendor_id=vendor_id,
        sensitivity=doc_sensitivity.name,
        findings=len(findings),
    )
    return result
