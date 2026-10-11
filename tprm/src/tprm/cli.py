"""TPRM CLI — tprm run / tprm policy explain / tprm gate verify."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer

from tprm.common.logging import configure_logging

app = typer.Typer(help="Privacy-Preserving Vendor Risk (TPRM) Pipeline CLI")
configure_logging()


@app.command("run")
def run_cmd(
    file: Path = typer.Argument(..., help="Path to vendor document (PDF/DOCX/XLSX)"),
    vendor: str = typer.Option(..., "--vendor", "-v", help="Vendor ID"),
    fake_llm: bool = typer.Option(True, "--fake-llm/--real-llm", help="Use FakeLLM (default: True)"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Run a full vendor risk assessment on a document."""
    from tprm.orchestrator import run_assessment

    if not file.exists():
        typer.echo(f"Error: File not found: {file}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Running assessment for vendor '{vendor}' on {file.name}...")

    try:
        result = asyncio.run(run_assessment(file, vendor_id=vendor, use_fake_llm=fake_llm))
    except Exception as exc:
        typer.echo(f"Assessment failed: {exc}", err=True)
        raise typer.Exit(1) from exc

    if output_json:
        typer.echo(json.dumps({
            "assessment_id": result.assessment_id,
            "sensitivity": result.document_sensitivity.name,
            "findings": [
                {"severity": f.severity, "score": f.score, "category": f.risk_category, "title": f.title}
                for f in result.findings
            ],
            "workflow_status": result.workflow_status,
        }, indent=2))
        return

    typer.echo(f"\n{'='*60}")
    typer.echo(f"ASSESSMENT COMPLETE — {result.assessment_id}")
    typer.echo(f"{'='*60}")
    typer.echo(f"Vendor:      {result.vendor_id}")
    typer.echo(f"File:        {result.filename}")
    typer.echo(f"Sensitivity: {result.document_sensitivity.name}")
    typer.echo(f"Gate:        {'PASSED ✓' if result.gate_report.passed else 'FAILED ✗'}")
    typer.echo(f"Blocks:      {result.gate_report.total_blocks} total, {result.gate_report.sensitive_path_blocks} sensitive")
    typer.echo(f"\nFindings ({len(result.findings)}):")
    for f in result.findings:
        typer.echo(f"  [{f.severity:8s}] {f.score:3d}/100  {f.risk_category:20s}  {f.title[:50]}")
    typer.echo(f"\nWorkflow status: {result.workflow_status}")
    typer.echo(f"\nTiming breakdown:")
    for stage, secs in result.stage_timings.items():
        typer.echo(f"  {stage:25s}: {secs:.2f}s")


@app.command("policy-explain")
def policy_explain_cmd(
    entity_type: str = typer.Option(..., "--entity-type", help="Entity type (e.g. EMAIL_ADDRESS)"),
    section_class: str = typer.Option("unknown", "--section-class", help="Section class"),
    doc_type: str = typer.Option("other", "--doc-type", help="Document type"),
) -> None:
    """Explain which policy rule fires for a given entity type and context."""
    from tprm.common.models import Block, NLPContext, PIIEntity, SensitivityLevel
    from tprm.policy.engine import PolicyEngine

    engine = PolicyEngine()
    block = Block(doc_id="explain", page=0, text="[EXPLAIN MODE]")
    entity = PIIEntity(
        block_id=block.id,
        start=0,
        end=14,
        entity_type=entity_type,
        text="[EXPLAIN MODE]",
        score=0.9,
        recognizer="explain",
    )
    ctx = NLPContext(
        block_id=block.id,
        doc_type=doc_type,
        section_class=section_class,
        section_sensitivity_floor=SensitivityLevel.INTERNAL,
    )

    decision = engine.decide(entity, ctx, block)
    explanation = engine.explain(decision)

    typer.echo(f"\nPolicy Explanation for entity_type={entity_type!r}")
    typer.echo(f"Context: section_class={section_class!r}, doc_type={doc_type!r}")
    typer.echo(f"{'='*60}")
    typer.echo(explanation)
    typer.echo(f"\nDecision: level={decision.level.name}, action={decision.action}")


@app.command("gate-verify")
def gate_verify_cmd(
    payload_file: Path = typer.Argument(..., help="Path to GateApprovedPayload JSON file"),
) -> None:
    """Verify the HMAC signature and run gate checks on a payload file."""
    from tprm.common.models import GateApprovedPayload
    from tprm.gate.verifier import verify_gate_approved
    from tprm.common.errors import SignatureError

    if not payload_file.exists():
        typer.echo(f"Error: File not found: {payload_file}", err=True)
        raise typer.Exit(1)

    try:
        data = json.loads(payload_file.read_text())
        payload = GateApprovedPayload.model_validate(data)
        verify_gate_approved(payload)
        typer.echo(f"✓ Signature valid — payload doc_id={payload.doc_id!r}")
        typer.echo(f"  Blocks: {len(payload.blocks)}, Gate passed: {payload.gate_report.passed}")
    except SignatureError as exc:
        typer.echo(f"✗ Signature INVALID: {exc}", err=True)
        raise typer.Exit(1) from exc
    except Exception as exc:
        typer.echo(f"✗ Verification failed: {exc}", err=True)
        raise typer.Exit(1) from exc


if __name__ == "__main__":
    app()
