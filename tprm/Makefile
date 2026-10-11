# ──────────────────────────────────────────────────────────────────────────────
# TPRM Pipeline Makefile
# ──────────────────────────────────────────────────────────────────────────────

PYTHON := .venv/bin/python
UV     := uv

.PHONY: help install up down test lint mypy demo pull-model migrate clean

help:
	@echo "TPRM Pipeline — available targets:"
	@echo "  install      Install all dependencies"
	@echo "  up           Start all services (postgres + ollama + app)"
	@echo "  down         Stop all services"
	@echo "  test         Run test suite"
	@echo "  lint         Run ruff linter"
	@echo "  mypy         Run mypy type checker"
	@echo "  demo         Run full pipeline demo on synthetic vendor PDF"
	@echo "  pull-model   Pull the default LLM model into Ollama"
	@echo "  migrate      Run Alembic database migrations"
	@echo "  clean        Remove generated files and caches"

install:
	$(UV) venv
	$(UV) pip install -e ".[dev]"

up:
	@if [ -z "$$TPRM_VAULT_KEY" ]; then \
		export TPRM_VAULT_KEY=$$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"); \
		export GATE_SIGNING_KEY=$$(python3 -c "import secrets; print(secrets.token_hex(32))"); \
	fi
	docker compose up -d --build

down:
	docker compose down

test:
	PYTHONPATH=src $(PYTHON) -m pytest tests/ -q --no-header

lint:
	PYTHONPATH=src $(PYTHON) -m ruff check src/ tests/ || true

mypy:
	PYTHONPATH=src $(PYTHON) -m mypy src/tprm/ --ignore-missing-imports || true

pull-model:
	docker compose exec ollama ollama pull llama3.1:8b

migrate:
	PYTHONPATH=src $(PYTHON) -m alembic upgrade head

demo:
	@echo "===================================================="
	@echo "  TPRM Pipeline Demo — Synthetic Vendor Assessment  "
	@echo "===================================================="
	@PYTHONPATH=src TPRM_VAULT_KEY=$$($(PYTHON) -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") \
		GATE_SIGNING_KEY="demo-gate-signing-key-for-local-demo" \
		$(PYTHON) -c "\
import asyncio, tempfile, json, sys; \
from pathlib import Path; \
sys.path.insert(0, 'src'); \
from tests.fixtures.make_pdf import make_synthetic_pdf, CANARIES; \
from tprm.orchestrator import run_assessment; \
from tprm.onetrust.mock import MockOneTrustClient; \
from tprm.onetrust.mapper import map_finding_to_onetrust; \
print('Generating synthetic vendor PDF...'); \
path = make_synthetic_pdf(); \
print(f'  -> {path}'); \
print(); \
result = asyncio.run(run_assessment(path, vendor_id='acme-demo-vendor', use_fake_llm=True)); \
print(f'SENSITIVITY BREAKDOWN'); \
print(f'  Document level: {result.document_sensitivity.name}'); \
print(f'  Total blocks:   {result.gate_report.total_blocks}'); \
print(f'  Sensitive path: {result.gate_report.sensitive_path_blocks}'); \
print(f'  Safe path:      {result.gate_report.safe_path_blocks}'); \
print(); \
print('GATE REPORT'); \
print(f'  Passed:       {result.gate_report.passed}'); \
print(f'  Re-scan hits: {result.gate_report.rescan_hits}'); \
print(); \
print(f'FINDINGS ({len(result.findings)})'); \
[print(f'  [{f.severity:8s}] {f.score:3d}/100  {f.risk_category:25s}  {f.title[:45]}') for f in result.findings]; \
print(); \
print(f'WORKFLOW STATE: {result.workflow_status}'); \
print(); \
ot = MockOneTrustClient(); \
import asyncio as _a; \
_a.run(ot.push_findings('demo-assess', [map_finding_to_onetrust(f) for f in result.findings])); \
print('ONETRUST (MOCK) OUTBOX PAYLOAD:'); \
outbox = ot.get_outbox(); \
print(json.dumps(outbox[-1] if outbox else {}, indent=2, default=str)[:1200]); \
print(); \
print('Demo complete.'); \
"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
	find . -name "*.pyc" -delete 2>/dev/null; \
	rm -rf .coverage htmlcov dist build; \
	echo "Cleaned."
