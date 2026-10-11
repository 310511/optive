---
inclusion: always
---

# Technical Steering: Privacy-Preserving Vendor Risk (TPRM) Pipeline

## Language and Runtime

- **Python 3.11+** exclusively. Use `match` statements, `TypeAlias`, `Self`, and `ParamSpec` where they improve clarity.
- **`uv`** is the package manager. All dependencies declared in `pyproject.toml` with pinned versions. No `requirements.txt`.
- **Pydantic v2** for all data models. Use `model_validator`, `field_validator`, and `model_config` (not v1 `@validator` / `class Config`).
- **FastAPI + Uvicorn** for the HTTP API. Async handlers throughout.
- **Typer** for the CLI.

## Core Dependencies

| Purpose | Library |
|---|---|
| PDF parsing | `pymupdf` (`fitz`) |
| DOCX parsing | `python-docx` |
| XLSX parsing | `openpyxl` |
| OCR | `pytesseract` + system Tesseract |
| PII detection | `presidio-analyzer`, `presidio-anonymizer` |
| NER / NLP | `spacy` `en_core_web_lg` |
| Embeddings | `sentence-transformers` `all-MiniLM-L6-v2` (local) |
| Encryption | `cryptography` (Fernet) |
| LLM client | `langchain-ollama` `ChatOllama` |
| Database | `sqlalchemy` 2 async + `asyncpg` + `alembic` |
| HTTP client | `httpx` |
| Logging | `structlog` |
| Tests | `pytest`, `pytest-asyncio`, `hypothesis` |
| Linting | `ruff` |
| Type checking | `mypy --strict` |

## Coding Standards

### Type Safety
- Every function and method must have full type annotations including return types.
- `mypy --strict` must pass with zero errors. No `# type: ignore` without a comment explaining why.
- Use `typing.Final` for constants, `typing.Literal` for constrained strings, `typing.TypedDict` for untyped dict shapes.

### No Raw PII in Code Paths
- **Logs**: never log `.text` of a `PIIEntity`, raw `Block.text` after detection, or vault plaintext. Log counts and IDs only.
- **Exceptions**: never include raw entity text in exception messages. Use entity type + block ID instead.
- **LLM prompts**: only `SanitizedBlock.text_sanitized` enters prompts. The gate verifies this before signing.
- **DB**: raw entity values only in `vault_entries.ciphertext` (Fernet-encrypted). All other tables store tokens or placeholders.

### Fail Closed
- Any `except` clause in the private zone (ingestion → gate) that cannot recover must mark the affected block/document as `RESTRICTED` and re-raise or return a degraded result that routes to sanitization. Never swallow exceptions and pass raw data forward.
- Unknown/unclassified entities → `RESTRICTED`. Missing config values → raise at startup, not at runtime.

### Determinism
- Policy decisions, severity scores, control mappings: fully deterministic. No LLM in the decision path.
- Tests must not depend on LLM output. Use `FakeLLM` in all unit and integration tests.
- Sanitization tokens: deterministic within a vendor assessment (same HMAC salt), non-deterministic across assessments.

### Architecture Boundaries
- Each stage package exports exactly one public interface function/class. See `structure.md` for the rule.
- The only shared types are in `src/tprm/common/models.py` and `src/tprm/common/errors.py`.
- No stage may import from another stage's internal modules (e.g., `pii.detector` must not import from `nlp.classifier`).

### Security Patterns
- Vault key: from `TPRM_VAULT_KEY` env var only. Never in YAML, never logged, never in exception messages.
- Gate signing key: from `GATE_SIGNING_KEY` env var only. Same rules.
- HMAC comparisons: use `hmac.compare_digest()` (constant-time), never `==`.
- Fernet: use `cryptography.fernet.Fernet`; key must be 32-byte URL-safe base64-encoded.

### Style
- `ruff` is the formatter and linter. Configuration in `pyproject.toml` under `[tool.ruff]`.
- Line length: 100 characters.
- Imports: `isort`-compatible order (ruff handles this).
- Docstrings: Google style on public functions; single-line for simple helpers.
- Compact over verbose: avoid wrapper classes that add no behaviour. Prefer `TypeAlias` and `NewType` over trivial wrapper classes.

## Infrastructure

- **Docker Compose** runs `app`, `postgres:16`, `ollama`.
- The `app` container is on an **internal-only Docker network** (`internal: true`). It cannot make external HTTP calls.
- Only the `onetrust-egress` sidecar service has external network access.
- Ollama is accessible to `app` via compose service name (e.g., `http://ollama:11434`); never via a public URL.
- Secrets (`TPRM_VAULT_KEY`, `GATE_SIGNING_KEY`) are mounted as Docker secrets or env vars; never baked into images.

## Testing

- Test files mirror source structure: `tests/unit/tprm/<package>/test_*.py`.
- `tests/security/` contains the leak-canary suite and gate bypass tests; these are the highest-priority tests.
- `tests/fixtures/` contains synthetic vendor document generators (not real vendor data).
- Use `pytest-asyncio` in `asyncio_mode = "auto"` for async test functions.
- Use `hypothesis` for property-based tests on policy engine (monotonicity) and sanitization (idempotence).
- Coverage target: ≥ 85 % overall, 100 % on `gate/` and `sanitize/`.
- Run `pytest tests/security -q` automatically on save of any file in `src/tprm/gate/` or `src/tprm/sanitize/` (via Kiro hook).
