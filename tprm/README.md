# Privacy-Preserving Vendor Risk (TPRM) Pipeline

Automates third-party risk assessments of vendor documents (PDF, DOCX, XLSX) while guaranteeing that raw PII never crosses the Security Gate into the AI analysis zone or downstream systems.

## Architecture

```mermaid
flowchart TD
    DOC["Vendor Document\n(PDF / DOCX / XLSX)"]

    subgraph PRIVATE["PRIVATE / TRUSTED ZONE (no egress)"]
        ING["1. Document Ingestion\nparser · ocr · segmenter"]
        PII["2. PII Detection\nPresidio + custom recognizers"]
        NLP["3. Local NLP\ncontext · relations · classifier"]
        POL["4. Policy Engine\nrule-based, deterministic"]
        SEN["5. Sensitivity Level\nPUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED"]
        SAN["6. Sanitization\nredact · tokenize · generalize · vault"]
    end

    GATE["SECURITY GATE\nRe-scan · Vault check · Entropy check\nHMAC-sign GateApprovedPayload"]

    subgraph PUBLIC_ZONE["AI / PUBLIC ZONE (sanitized data only)"]
        AI["7. AI Risk Analysis\nLangChain → Ollama (local)"]
        RISK["8. Risk Engine\nextract · categorize · severity · controls"]
        WF["9. TPRM Workflow\nstate machine · escalation · approval"]
        OT["10. OneTrust TPRM\nmock (default) · HTTP (opt-in)"]
    end

    DOC --> ING --> PII --> NLP --> POL --> SEN
    SEN -->|"SAFE (≤INTERNAL)"| GATE
    SEN -->|"SENSITIVE (≥CONFIDENTIAL)"| SAN --> GATE
    GATE --> AI --> RISK --> WF --> OT
```

## Threat Model

### Assets
- **Raw vendor PII** — names, emails, SSNs, payment data in vendor documents
- **Credentials/secrets** — API keys, private keys found in vendor docs
- **Internal topology** — our org's hostnames, IP ranges, system names
- **Assessment findings** — risk ratings and control gaps
- **Vault key** — Fernet master key for token vault

### Trust Boundaries

| Boundary | Enforced By |
|---|---|
| File input → ingestion | Magic-byte detection, size/page limits, zip-bomb guard |
| Private zone → gate | Docker `internal: true` network; gate is the only crossing point |
| Gate → AI zone | HMAC signature; `verify_gate_approved()` at AI entry; type system |
| AI zone → OneTrust | Outbox payload validator (Presidio re-scan); opt-in egress container |

### Security Gate Guarantees

**Does guarantee:**
- No raw PII string (verbatim or normalised) crosses the gate
- No high-entropy string (key material) crosses the gate
- Every crossing payload is HMAC-signed; tampering is detectable downstream
- Audit trail exists for every gate pass/quarantine event

**Does NOT guarantee:**
- Protection against a compromised Ollama model pre-trained on vendor data
- Protection against DB-level access (vault ciphertext needs the vault key)
- Side-channel inference from structured but sanitized data patterns

## Setup

### Prerequisites

- Python 3.11+
- `uv` package manager (`pip install uv`)
- Docker + Docker Compose (for full stack)
- Tesseract OCR (`brew install tesseract` on macOS)

### Quick Start (local testing)

```bash
# Clone and set up
git clone <repo> && cd tprm
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Set required secrets
export TPRM_VAULT_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export GATE_SIGNING_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Run demo (uses FakeLLM — no Ollama needed)
make demo

# Run tests
make test

# Lint and type check
make lint
make mypy
```

### Full Stack (with Ollama)

```bash
# Set secrets in environment or .env file
export TPRM_VAULT_KEY=<your-fernet-key>
export GATE_SIGNING_KEY=<your-signing-key>

# Start all services
make up

# Pull the LLM model (first time only)
make pull-model

# Run database migrations
make migrate

# Access API
curl -H "X-API-Key: dev-insecure-key" http://localhost:8000/api/v1/healthz
```

## Configuration

### Required Environment Variables

| Variable | Description |
|---|---|
| `TPRM_VAULT_KEY` | Fernet key for token vault (32-byte base64-encoded) |
| `GATE_SIGNING_KEY` | HMAC signing key for gate payloads |

### Optional Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TPRM_DATABASE_URL` | `postgresql+asyncpg://tprm:tprm@localhost:5432/tprm` | DB connection string |
| `TPRM_OLLAMA_URL` | `http://ollama:11434` | Ollama base URL |
| `TPRM_LLM_MODEL` | `llama3.1:8b` | Ollama model name |
| `TPRM_ONETRUST_ADAPTER` | `mock` | `mock` or `http` |
| `TPRM_LOG_LEVEL` | `INFO` | Log level |
| `TPRM_LOG_JSON` | `false` | JSON log output |
| `TPRM_ALLOW_DETOKENIZE` | `false` | Enable vault detokenization API |

## API Reference

All endpoints require `X-API-Key` header.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/assessments` | Upload document and start assessment |
| `GET` | `/api/v1/assessments/{id}` | Get assessment status |
| `GET` | `/api/v1/assessments/{id}/findings` | Get findings list |
| `POST` | `/api/v1/assessments/{id}/transition` | Workflow state transition |
| `GET` | `/api/v1/audit/{doc_id}` | Get audit log for document |
| `GET` | `/api/v1/healthz` | Liveness check |

## CLI

```bash
# Full pipeline assessment
tprm run vendor-doc.pdf --vendor acme-corp

# Explain policy decision for an entity type
tprm policy-explain --entity-type EMAIL_ADDRESS --section-class access_control

# Verify a gate payload file
tprm gate-verify payload.json
```

## Testing

```bash
# Full test suite
make test

# Security tests only (leak-canary, gate bypass)
PYTHONPATH=src pytest tests/security/ -v

# Coverage report
PYTHONPATH=src pytest tests/ --cov=src/tprm --cov-report=html
```

## Key Design Decisions

1. **Policy engine is fully deterministic** — no LLM involvement in sensitivity or routing decisions.
2. **Gate fails closed** — any exception, ambiguity, or low confidence → RESTRICTED/quarantine.
3. **Vault detokenization disabled by default** — requires `TPRM_ALLOW_DETOKENIZE=true` + reason string + audit event.
4. **`MockOneTrustClient` is the default** — HTTP egress requires explicit opt-in via `TPRM_ONETRUST_ADAPTER=http`.
5. **FakeLLM for tests** — all tests use `FakeLLM` (deterministic) behind the same `LLMBackend` protocol.
6. **Approver ≠ creator enforced** for High/Critical findings at the type level.
