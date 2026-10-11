---
inclusion: always
---

# Structure Steering: Privacy-Preserving Vendor Risk (TPRM) Pipeline

## Repository Layout

```
tprm/
├── pyproject.toml              # uv project, ruff, mypy config
├── docker-compose.yml          # app + postgres + ollama + onetrust-egress
├── Makefile                    # up / down / test / lint / mypy / demo / pull-model / migrate
├── README.md
│
├── config/
│   ├── policy.yaml             # org policy, entity impact table, allow/deny lists
│   ├── risk_taxonomy.yaml      # 11 risk categories with weights
│   ├── controls.yaml           # ISO 27001 / SOC 2 TSC / NIST CSF 2.0 catalog
│   └── workflow.yaml           # escalation rules, SLA durations, approval roles
│
├── src/tprm/
│   ├── common/
│   │   ├── models.py           # ALL shared Pydantic v2 models and enums
│   │   ├── errors.py           # Custom exception hierarchy
│   │   ├── crypto.py           # Fernet helpers, HMAC sign/verify, token derivation
│   │   ├── logging.py          # structlog config + PII-scrubbing processor
│   │   ├── audit.py            # Hash-chained audit log writer + verifier
│   │   └── config.py           # Settings (Pydantic BaseSettings v2)
│   │
│   ├── ingestion/              # Stage 1 — Document parsing
│   │   ├── parser.py           # PUBLIC: parse(path) -> Document
│   │   ├── ocr.py              # Internal: OCR helpers
│   │   └── segmenter.py        # Internal: section_path + chunking
│   │
│   ├── pii/                    # Stage 2 — PII detection
│   │   ├── detector.py         # PUBLIC: detect(blocks, config) -> list[PIIEntity]
│   │   └── recognizers.py      # Internal: custom PatternRecognizer subclasses
│   │
│   ├── nlp/                    # Stage 3 — Local NLP
│   │   ├── context.py          # PUBLIC: build_context(block, entities, doc) -> NLPContext
│   │   ├── relations.py        # PUBLIC: build_relations(blocks, entities) -> list[Relation]
│   │   ├── classifier.py       # PUBLIC: classify_doc / classify_section
│   │   └── prototypes/         # Pre-computed .npy embedding arrays for doc/section types
│   │
│   ├── policy/                 # Stage 4 — Policy engine
│   │   ├── engine.py           # PUBLIC: PolicyEngine.decide / explain
│   │   └── rules.py            # Internal: PolicyRule DSL + matcher
│   │
│   ├── sensitivity/            # Stage 5 — Sensitivity scoring + routing
│   │   ├── levels.py           # PUBLIC: score_block / score_document
│   │   └── scorer.py           # PUBLIC: route(block) -> "SAFE" | "SENSITIVE"
│   │
│   ├── sanitize/               # Stage 6 — Sanitization
│   │   ├── pipeline.py         # PUBLIC: sanitize_pipeline(blocks, assessment_id) -> list[SanitizedBlock]
│   │   ├── redact.py           # Internal
│   │   ├── tokenize.py         # Internal
│   │   ├── generalize.py       # Internal
│   │   └── vault.py            # Internal: token vault (Postgres + Fernet)
│   │
│   ├── gate/                   # Stage 7 — Security Gate (CRITICAL)
│   │   ├── gate.py             # PUBLIC: process(blocks, doc_id, vendor_id) -> GateApprovedPayload
│   │   ├── signing.py          # Internal: HMAC sign/verify canonical payload
│   │   └── verifier.py         # PUBLIC: verify_gate_approved(payload) — used by ai/analyzer.py
│   │
│   ├── ai/                     # Stage 8 — AI Risk Analysis
│   │   ├── analyzer.py         # PUBLIC: analyze(payload: GateApprovedPayload) -> AIRiskResult
│   │   ├── prompts.py          # Internal: prompt templates + injection-hardened builder
│   │   └── schemas.py          # Internal: AIRiskResult / RawRisk Pydantic models + JSON schema
│   │
│   ├── risk/                   # Stage 9 — Risk Engine
│   │   ├── extractor.py        # PUBLIC: extract(result, blocks) -> list[NormalisedRisk]
│   │   ├── categorizer.py      # PUBLIC: categorize(risk) -> RiskCategory
│   │   ├── severity.py         # PUBLIC: score(risk, vendor_meta) -> SeverityScore
│   │   ├── controls.py         # PUBLIC: map_controls(risk, section_class) -> list[ControlRef]
│   │   └── recommender.py      # PUBLIC: recommend(finding) -> str
│   │
│   ├── workflow/               # Stage 10 — TPRM Workflow
│   │   ├── models.py           # Workflow-specific models (AssessmentStatus, transitions)
│   │   ├── state_machine.py    # PUBLIC: WorkflowStateMachine
│   │   ├── escalation.py       # PUBLIC: EscalationChecker
│   │   └── approval.py         # PUBLIC: approve(finding_id, approver_id, decision)
│   │
│   ├── onetrust/               # Stage 11 — OneTrust TPRM adapter
│   │   ├── base.py             # PUBLIC: OneTrustClient ABC
│   │   ├── mock.py             # PUBLIC: MockOneTrustClient (default)
│   │   ├── client.py           # PUBLIC: HttpOneTrustClient (opt-in)
│   │   └── mapper.py           # PUBLIC: map_finding_to_onetrust()
│   │
│   ├── api/
│   │   ├── main.py             # FastAPI app factory
│   │   └── routes.py           # All REST endpoints
│   │
│   ├── cli.py                  # Typer CLI: run / policy explain / gate verify
│   └── orchestrator.py         # run_assessment() — async pipeline coordinator
│
├── tests/
│   ├── unit/tprm/              # Unit tests mirroring src/tprm/ structure
│   ├── integration/            # Cross-stage integration tests
│   ├── security/               # Leak-canary, gate bypass, fail-closed, prompt-injection
│   └── fixtures/               # Synthetic document generators (make_pdf.py etc.)
│
├── alembic/                    # DB migrations
│   └── versions/
│
└── .kiro/
    ├── specs/tprm-pipeline/    # requirements.md, design.md, tasks.md
    ├── steering/               # product.md, tech.md, structure.md (this file)
    └── hooks/                  # security-test-on-save.json
```

## The One Rule for Cross-Stage Imports

> **One package per architecture box. No cross-stage imports except via `common/models.py` and the stage's own public interface.**

This means:
- `pii/detector.py` may import from `common/models.py` ✓
- `nlp/context.py` may import `PIIEntity` from `common/models.py` ✓
- `nlp/context.py` must NOT import from `pii/detector.py` or `pii/recognizers.py` ✗
- `ai/analyzer.py` may call `gate/verifier.verify_gate_approved()` ✓ (verifier is gate's public interface)
- `ai/analyzer.py` must NOT import from `gate/signing.py` or `gate/gate.py` ✗
- `orchestrator.py` is the only module that imports from multiple stage public interfaces ✓

## Architecture Box → Package Mapping (exact)

| Architecture Box | Package Path |
|---|---|
| Document Ingestion | `src/tprm/ingestion/` |
| PII Detection | `src/tprm/pii/` |
| Local NLP | `src/tprm/nlp/` |
| Policy Engine | `src/tprm/policy/` |
| Sensitivity Level | `src/tprm/sensitivity/` |
| Sanitization | `src/tprm/sanitize/` |
| Security Gate | `src/tprm/gate/` |
| AI Risk Analysis | `src/tprm/ai/` |
| Risk Engine | `src/tprm/risk/` |
| TPRM Workflow | `src/tprm/workflow/` |
| OneTrust TPRM | `src/tprm/onetrust/` |

Each row is exactly one box in the architecture diagram. A reviewer must be able to point at any box and find exactly one directory.
