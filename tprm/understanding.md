# TPRM System — Complete Component Understanding

> **What this system does in one sentence:**  
> A vendor document (PDF/DOCX/XLSX) goes in, all PII is detected and scrubbed behind a cryptographic security gate, a local LLM analyzes the sanitized text for security risks, and structured findings come out — with a full audit trail and an approval workflow attached.

---

## Table of Contents

1. [Big Picture — How It All Fits](#1-big-picture--how-it-all-fits)
2. [Data Flow — End to End](#2-data-flow--end-to-end)
3. [Common — The Foundation](#3-common--the-foundation)
4. [Stage 1 — Ingestion](#4-stage-1--ingestion)
5. [Stage 2 — PII Detection](#5-stage-2--pii-detection)
6. [Stage 3 — NLP](#6-stage-3--nlp)
7. [Stage 4 & 5 — Policy Engine + Sensitivity](#7-stages-4--5--policy-engine--sensitivity)
8. [Stage 6 — Sanitization](#8-stage-6--sanitization)
9. [Stage 7 — Security Gate](#9-stage-7--security-gate)
10. [Stage 8 — AI Risk Analysis](#10-stage-8--ai-risk-analysis)
11. [Stage 9 — Risk Engine](#11-stage-9--risk-engine)
12. [Stage 10 & 11 — Workflow + OneTrust](#12-stages-10--11--workflow--onetrust)
13. [API Layer](#13-api-layer)
14. [CLI](#14-cli)
15. [Orchestrator — The Conductor](#15-orchestrator--the-conductor)
16. [Security Guarantees Built Into the Architecture](#16-security-guarantees-built-into-the-architecture)
17. [Config Files](#17-config-files)

---

## 1. Big Picture — How It All Fits

This is a **Third Party Risk Management (TPRM)** pipeline. When your organisation receives a security document from a vendor (e.g. a SOC 2 report, DPA, security questionnaire), you run it through this system. The system:

1. **Parses** the document into text blocks
2. **Detects PII** (emails, SSNs, API keys, etc.) in those blocks
3. Runs **NLP** to understand what section of the document each block belongs to
4. Applies a **policy engine** to decide what to do with each piece of PII (redact it, tokenize it, generalise it, or keep it)
5. **Sanitizes** the text — replaces PII with safe placeholders
6. Passes everything through a **Security Gate** that cryptographically signs the sanitized output before it ever touches an LLM
7. Sends the signed, sanitized text to a **local LLM** (Ollama) for risk analysis
8. The LLM's output is processed by a **risk engine** that categorizes, scores, and generates findings
9. Findings go through a **workflow** (Draft → Review → Escalated/Accepted)
10. Results are optionally pushed to **OneTrust** for compliance tracking

The key architectural principle is **privacy-by-design**: raw PII values never reach the LLM, never appear in logs, and can only be detokenized with an explicit environment flag and a documented reason.

---

## 2. Data Flow — End to End

```
Raw file bytes (PDF / DOCX / XLSX)
    │
    ▼
[ingestion/parser.py]
    Parses into → Document (list of Block objects)
    │
    ▼
[ingestion/segmenter.py]
    Assigns section_path to each Block (heading hierarchy)
    │
    ▼
[pii/detector.py]
    Detects PII → list[PIIEntity]
    │
    ▼
[nlp/classifier.py + context.py + relations.py]
    Classifies doc type, section type, builds NLPContext + Relations
    │
    ▼
[policy/engine.py]
    For each entity: decides action (keep / redact / tokenize / generalize)
    → PolicyDecision per entity
    │
    ▼
[sensitivity/levels.py + scorer.py]
    Scores each block (PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED)
    Routes block to SAFE path or SENSITIVE path
    │
    ├── SAFE path (PUBLIC/INTERNAL blocks) ──────────────────────────────┐
    │                                                                    │
    └── SENSITIVE path (CONFIDENTIAL/RESTRICTED blocks)                 │
          │                                                             │
          ▼                                                             │
    [sanitize/pipeline.py]                                              │
         redact.py / tokenize.py / generalize.py                       │
         vault.py (stores encrypted raw values)                        │
         → SanitizedBlock (no raw PII)                                 │
                                                                        │
    ◄───────────────────────────────────────────────────────────────────┘
    (all blocks, SAFE and SENSITIVE, merge here)
    │
    ▼
[gate/gate.py]
    5-step validation: re-scan, vault leak check,
    token grammar, entropy check, HMAC signing
    → GateApprovedPayload (signed)
    │
    ▼
[ai/analyzer.py]
    Verifies HMAC signature first
    Groups blocks by section_class → calls LLM per section chunk
    → AIRiskResult (list of RawRisk)
    │
    ▼
[risk/extractor.py + categorizer.py + severity.py + controls.py + recommender.py]
    Normalizes, categorizes, scores, maps controls, generates recommendations
    → list[Finding]
    │
    ▼
[workflow/state_machine.py + escalation.py]
    Auto-escalates Critical findings
    Sets workflow status
    │
    ▼
[onetrust/mapper.py + client.py]
    Pushes findings to OneTrust (or MockOneTrustClient in dev)
    │
    ▼
AssessmentResult (returned to API / CLI caller)
```

---

## 3. Common — The Foundation

These modules are imported by almost everything else. They define the rules of the road.

### `common/models.py` — The Data Contracts

**The single most important file in the project.** Every stage communicates exclusively through the Pydantic models defined here. No stage is allowed to define its own cross-stage types.

Key models in pipeline order:

| Model | What it is |
|---|---|
| `SensitivityLevel` | IntEnum: PUBLIC=0, INTERNAL=1, CONFIDENTIAL=2, RESTRICTED=3. Integer ordering means `max()` comparisons work correctly. |
| `Block` | One unit of extracted text from a document. Has `id`, `doc_id`, `page`, `section_path` (heading hierarchy), `text`, `bbox`, `source` (native/ocr/table_cell). `__repr__` deliberately omits `.text` to prevent PII leaking into logs. |
| `DocumentMeta` | File-level metadata: size, page count, format, OCR flag, vendor criticality (0.8–1.5). |
| `Document` | The full parsed document: `doc_id`, `vendor_id`, `filename`, `sha256`, `blocks`, `meta`. |
| `PIIEntity` | A detected PII span: `block_id`, character `start`/`end`, `entity_type`, `text` (never logged), `score`, `recognizer`. |
| `Relation` | A directed edge between two entities: `source → target`, `relation_type` (e.g. `person_email`, `system_ip`). |
| `NLPContext` | NLP features for a block: `doc_type`, `section_class`, confidences, `relations`, `is_example`, `is_negated`, `section_sensitivity_floor`. |
| `PolicyDecision` | What to do with one entity: `action` is one of `keep/redact/tokenize/generalize`, plus `level`, `rule_id`, `rationale`. |
| `ClassifiedBlock` | A Block enriched with entities + NLPContext + PolicyDecisions + computed `block_level`. A model validator ensures block_level is always monotonically non-decreasing. |
| `Transform` | Record of one sanitization operation: `entity_type`, `action`, character `start`/`end`, `placeholder` (the replacement string). |
| `SanitizedBlock` | A block after sanitization. Contains `text_sanitized` (no raw PII) and `applied` list of Transforms. |
| `GateReport` | Gate summary: block counts, re-scan hits, rerouted blocks, quarantine flag, pass flag. |
| `GateApprovedPayload` | The only type the AI stage accepts. Contains sanitized blocks + gate report + HMAC `signature`. `canonical_bytes()` gives deterministic JSON bytes for signing (excludes `signature` field itself). |
| `RawRisk` | LLM output item: `title`, `description`, `evidence_block_ids`, `claimed_category`, `confidence`. |
| `AIRiskResult` | Wrapper for LLM output: `items: list[RawRisk]`. |
| `ControlRef` | Reference to a framework control: `control_id`, `framework` (ISO27001/SOC2/NIST_CSF), `ref`, `name`, `gap_status` (missing/partial/satisfied). |
| `Finding` | Fully processed risk finding: `severity`, `score` (0–100), `controls`, `recommendation`, `description`, `section_label`, `entity_types_found`. |
| `AuditEvent` | Hash-chained audit log entry. Each event's `hash` is SHA-256 over its content + `prev_hash` of the previous event — tamper-evident. |
| `AssessmentResult` | Top-level output: `assessment_id`, `vendor_id`, `document_sensitivity`, `gate_report`, `findings`, `workflow_status`, `stage_timings`. |

---

### `common/config.py` — Settings

Pydantic `BaseSettings` that reads configuration from environment variables (prefixed `TPRM_`) and a `.env` file. Secrets (database URL, signing keys, OneTrust credentials) only come from env vars — never from YAML.

It lazy-loads four YAML files as properties:
- `.policy` → `config/policy.yaml`
- `.risk_taxonomy` → `config/risk_taxonomy.yaml`
- `.controls` → `config/controls.yaml`
- `.workflow` → `config/workflow.yaml`

`get_settings()` returns a cached singleton (via `@lru_cache`). `override_settings(**kwargs)` patches the cache for testing.

---

### `common/crypto.py` — Cryptographic Primitives

All crypto in the system lives here. Nothing does its own crypto elsewhere.

| Function | What it does |
|---|---|
| `load_vault_key()` | Reads `TPRM_VAULT_KEY` env var (must be a valid Fernet key). |
| `load_gate_signing_key()` | Reads `GATE_SIGNING_KEY` env var. |
| `fernet_encrypt / fernet_decrypt` | Symmetric encryption for the token vault. |
| `hmac_sign(data, key) → str` | HMAC-SHA256 hex digest. Used by the gate. |
| `hmac_verify(data, key, sig) → bool` | Constant-time comparison. |
| `derive_token(entity_text, entity_type, salt) → str` | Returns `<<ENTITY_TYPE_xxxxxxxx>>` — deterministic within one assessment, non-deterministic across assessments. |
| `derive_assessment_salt(vendor_id, assessment_id, master_key) → str` | Per-assessment HMAC-derived salt used for tokenization. |
| `shannon_entropy / max_window_entropy` | Used by the gate's entropy check to detect potential key material. |

---

### `common/audit.py` — The Audit Log

Async, append-only, hash-chained audit log. Every significant event in the pipeline appends an `AuditEvent` with a SHA-256 hash that chains to the previous event. Tampering with any event breaks all subsequent hashes.

`get_audit_log()` returns a module-level singleton. `verify_chain()` can validate the full chain. Stores only entity type counts — never raw PII values.

---

### `common/errors.py` — Exception Hierarchy

Every exception in the system derives from `TPRMError`. Organized by pipeline stage:

- **Ingestion:** `UnsupportedFormat`, `FileTooLarge`, `TooManyPages`, `ZipBombDetected`
- **PII/NLP:** `PIIDetectionError`, `NLPError`
- **Policy:** `PolicyConfigError`, `PolicyDecisionError`
- **Sanitization:** `SanitizationError`, `VaultError`, `DetokenizationDisabled`
- **Gate:** `GateViolation` (most critical — fail-closed), `SignatureError`, `EntropyViolation`, `MalformedPlaceholder`
- **AI:** `LLMError`, `LLMParseError`
- **Risk:** `RiskEngineError`
- **Workflow:** `InvalidTransition`, `ApprovalViolation`, `RiskAcceptanceError`
- **Integration:** `OneTrustError`, `PayloadViolation`

Error messages are required to never contain raw PII values — only entity types and block IDs.

---

## 4. Stage 1 — Ingestion

**Goal:** Turn raw bytes of a vendor document into a structured list of `Block` objects.

### `ingestion/parser.py`

**Public interface:** `parse(path: Path, vendor_id: str) -> Document`

**What it does step by step:**
1. Reads raw bytes, checks file size (raises `FileTooLarge` if over policy limit, default 50 MB)
2. Computes SHA-256 of the file
3. Detects format by **magic bytes** — not file extension:
   - `%PDF` → PDF
   - `PK\x03\x04` (ZIP) → inspects ZIP entries to distinguish DOCX from XLSX
   - Anything else → `UnsupportedFormat`
4. Dispatches to the appropriate parser
5. Wraps all blocks into a `Document`
6. Calls `segmenter.segment(doc)` to assign heading hierarchies

**PDF parsing (`_parse_pdf`):**
- Uses PyMuPDF (`fitz`)
- If a page has very little native text (below `ocr_sparse_threshold`) → calls OCR
- Otherwise extracts native text blocks with bounding boxes

**DOCX parsing (`_parse_docx`):**
- Runs a zip-bomb check first (raises `ZipBombDetected` if decompression ratio > 50x)
- Uses `python-docx` for paragraphs (heading styles detected), table cells, and embedded images (OCR'd)

**XLSX parsing (`_parse_xlsx`):**
- Zip-bomb check first
- Uses `openpyxl` (read-only, data-only mode)
- Sets `section_path = [sheet_name, cell_address]`
- Flags hidden sheets with `[HIDDEN_SHEET]` prefix

---

### `ingestion/ocr.py`

**What it does:** Runs Tesseract OCR on a PDF page pixmap or raw image bytes.

- `ocr_pixmap(pixmap, ...)` — converts PyMuPDF pixmap to PIL Image, runs `pytesseract.image_to_data`
- Low-confidence words (below threshold) are tagged `[LOW_CONF]` but retained
- If pytesseract isn't installed: returns empty string gracefully (degradation, not crash)

---

### `ingestion/segmenter.py`

**What it does:** Assigns `section_path` (heading hierarchy) to each `Block`.

- For PDF: uses heuristics to detect headings (all-caps text, numbered patterns like `2.1`, title-case 2–10 word lines). Maintains a hierarchy stack as it reads through blocks.
- For DOCX/XLSX: the parser already set `section_path` from Word heading styles / sheet names — nothing to do.

After this stage, every block knows where in the document it lives (e.g. `["2. Security Controls", "2.1 Access Management"]`).

---

## 5. Stage 2 — PII Detection

**Goal:** Find every piece of personally identifiable information across all blocks.

### `pii/detector.py`

**Public interface:** `detect(blocks, thresholds, org_domains) -> list[PIIEntity]`

**What it does:**
1. Builds (and caches) a Presidio `AnalyzerEngine`
2. Tries to load a locally-installed spaCy model (`en_core_web_lg` or `en_core_web_sm`) for NER-backed detection
3. Falls back to **pattern-only mode** (`NoOpNlpEngine`) if no spaCy model is installed — the system still works, just without NER-based PERSON/ORG detection
4. Registers all custom TPRM recognizers (see below)
5. For each block: runs Presidio, filters by per-entity-type confidence thresholds
6. Resolves overlapping spans — longest span wins; ties broken by highest confidence score
7. Logs only entity type counts — never the text

Detects 20+ entity types: `EMAIL_ADDRESS`, `PHONE_NUMBER`, `IBAN_CODE`, `CREDIT_CARD`, `US_SSN`, `IP_ADDRESS`, `MAC_ADDRESS`, `CREDENTIAL_URL`, `API_KEY`, `PEM_PRIVATE_KEY`, `INTERNAL_HOSTNAME`, `PERSON`, `ORG`, `LOCATION`, `EMPLOYEE_ID`, `CONTRACT_NUMBER`, `BANK_ACCOUNT`, and more.

---

### `pii/recognizers.py`

**What it does:** Custom Presidio `PatternRecognizer` subclasses for types that Presidio doesn't cover out of the box.

| Recognizer | How it works |
|---|---|
| `IBANRecognizer` | Regex + ISO 13616 modulo-97 checksum validation |
| `CreditCardRecognizer` | 16-digit pattern + Luhn algorithm validation |
| `MacAddressRecognizer` | Colon and hyphen MAC formats |
| `CredentialURLRecognizer` | `user:pass@host` URL pattern, score 0.9 |
| `APIKeyRecognizer` | AWS `AKIA` prefix, GitHub `ghp_`/`gho_`, Slack `xoxb-`, Stripe `sk_live/test`. Generic 32+ char strings require Shannon entropy > 4.5 bits to qualify. |
| `PEMPrivateKeyRecognizer` | PEM header `-----BEGIN ... PRIVATE KEY-----` |
| `InternalHostnameRecognizer` | `.internal/.corp/.intra/.local/.lan` suffixes + configurable org domains |
| `EmployeeIDRecognizer` | `EMP-\d{4,8}` patterns |
| `ContractNumberRecognizer` | `CONT-`, `PO-`, and generic contract patterns |
| `BankAccountRecognizer` | 8-12 digit accounts, routing+account patterns |

`build_custom_recognizers(org_domains=None)` instantiates all of them and returns a list for registration. Called by both the main detector and the gate's independent re-scanner.

---

## 6. Stage 3 — NLP

**Goal:** Understand the context around detected PII — what type of document is this, what section is each block in, and how are entities related to each other.

### `nlp/classifier.py`

- `classify_doc(text) -> Classification` — classifies the whole document type (e.g. `soc2_report`, `dpa`, `security_questionnaire`, `unknown`) using a sentence-transformer model or keyword heuristics as fallback
- `classify_section(text) -> Classification` — classifies individual blocks into section types: `access_control`, `encryption`, `incident_response`, `bc_dr`, `subprocessors`, `data_retention`, `audit_scope`, `exceptions_qualifications`, `unknown`

The section classification is critical — it feeds into both the policy engine (different rules for different sections) and the AI analyzer (sections are analyzed separately by the LLM).

---

### `nlp/context.py`

- `build_context(block, entities, doc) -> NLPContext` — constructs the initial context object for a block, including neighbor text window for context
- `update_context_with_classification(ctx, doc_type, doc_type_confidence, section_class, section_class_confidence) -> NLPContext` — enriches context with classifier output

The `NLPContext` also carries `is_example` (does this block look like a sample/example?) and `is_negated` (is the entity mentioned in a negation context?). These influence policy decisions.

---

### `nlp/relations.py`

- `build_relations(blocks, entities) -> list[Relation]` — builds a graph of directed relationships between detected entities. Example relations: `person_email` (a person name and email appear in the same block), `system_ip` (a hostname and IP are co-located), `person_role` (name next to a job title)
- `get_canonical_ids(entities) -> dict[str, str]` — maps entity IDs to canonical IDs for deduplication (same person appearing multiple times)

Relations are used by the sanitization stage — specifically `generalize.py` uses the relation graph to replace `PERSON` entities with `[PERSON:ROLE]` when a role can be inferred from context.

---

## 7. Stages 4 & 5 — Policy Engine + Sensitivity

**Goal:** Decide what to do with each piece of PII, and assign a sensitivity level to each block.

### `policy/engine.py`

**Public interface:** `PolicyEngine().decide(entity, ctx, block) -> PolicyDecision`

The policy engine loads rules from `config/policy.yaml` (and `policy/rules.py`) and makes a per-entity decision:

- `keep` — low-risk entity in a safe context (e.g. an ORG name in a public section)
- `redact` — replace with `[REDACTED:TYPE]` — for high-risk entities where the value itself is useless to the LLM
- `tokenize` — replace with a reversible token `<<TYPE_xxxxxxxx>>` — for entities where the LLM needs to track "this entity appears in multiple places" without seeing the actual value
- `generalize` — replace with a semantic placeholder like `[PERSON:MANAGER]` or `[INTERNAL_IP_RANGE]` — preserves meaning, removes specificity

Decision factors:
- Entity type (API keys always get redacted; email addresses in `access_control` sections get tokenized)
- Section sensitivity floor (some sections like `access_control` have a minimum CONFIDENTIAL floor)
- NLP context flags (`is_example=True` may reduce severity; `is_negated=True` reduces risk)
- Document type (a SOC2 report is treated differently from a raw data export)

---

### `sensitivity/levels.py`

- `score_block(classified: ClassifiedBlock) -> ClassifiedBlock` — computes `block_level = max(max decision level, section floor, current level)`. Monotonically non-decreasing — you can never lower a block's sensitivity.
- `score_document(classified_blocks) -> SensitivityLevel` — returns `max(b.block_level for b in all_blocks)`. The document is as sensitive as its most sensitive block.

---

### `sensitivity/scorer.py`

- `route(classified: ClassifiedBlock) -> "SAFE" | "SENSITIVE"` — `PUBLIC` or `INTERNAL` → `"SAFE"` (skip sanitization, go directly to gate); `CONFIDENTIAL` or `RESTRICTED` → `"SENSITIVE"` (must go through sanitization). Any exception → `"SENSITIVE"` (fail-closed).

---

## 8. Stage 6 — Sanitization

**Goal:** Replace all PII in SENSITIVE blocks with safe placeholders before the text crosses the privacy boundary.

### `sanitize/pipeline.py`

**Public interface:** `sanitize_pipeline(blocks, assessment_id, vendor_id) -> list[SanitizedBlock]`

**Flow:**
1. Derives a per-assessment HMAC salt from `vendor_id + assessment_id + vault_key`
2. For SAFE blocks (PUBLIC/INTERNAL): emits `SanitizedBlock` with `text_sanitized = original text`, no transforms
3. For SENSITIVE blocks (CONFIDENTIAL/RESTRICTED): calls `_sanitize_block`
4. Applies transforms in this order: **generalize first** → **tokenize second** → **redact last** (all right-to-left within each pass to preserve offset correctness)
5. Idempotent: skips spans that already look like placeholders

---

### `sanitize/redact.py`

Replaces spans with `[REDACTED:EMAIL_ADDRESS]` style placeholders. Processes right-to-left (from end to start) so that replacing one span doesn't shift the character offsets of earlier spans.

---

### `sanitize/tokenize.py`

Replaces spans with deterministic HMAC-derived tokens: `<<EMAIL_ADDRESS_a3f92c1d>>`. The same email address in the same assessment always gets the same token — so the LLM can see "this token appears in block A and block B" without knowing the actual email.

Returns a `token_map` (`{token: raw_value}`) that gets stored in the vault.

---

### `sanitize/generalize.py`

Semantic replacement — preserves meaning while removing specificity:

| Entity type | What it becomes |
|---|---|
| `IP_ADDRESS` | `[INTERNAL_IP_RANGE]` or `[EXTERNAL_IP]` (checks RFC1918 ranges) |
| `INTERNAL_HOSTNAME` | `[HOST:prod]`, `[HOST:staging]`, `[HOST:dev]`, etc. (env detection) |
| `PERSON` | `[PERSON:MANAGER]`, `[PERSON:ENGINEER]`, etc. (from relation graph) or `[PERSON:UNKNOWN]` |
| `DATE_TIME` | Year only: `2023` or `[DATE:YEAR]` |
| Anything else | `[EMAIL_ADDRESS:GENERALIZED]` style |

---

### `sanitize/vault.py`

Fernet-encrypted in-memory token vault. Stores raw PII values as ciphertext, keyed by `(assessment_id, token)`.

- `store(token, raw_value, entity_type, assessment_id)` — encrypts and stores
- `lookup_raw_values(assessment_id) -> list[str]` — decrypts all values for the gate's leak check (the only legitimate path to decryption outside of detokenization)
- `detokenize(token, assessment_id, reason) -> str` — requires `TPRM_ALLOW_DETOKENIZE=true` env var AND a non-empty reason string. Logs the access. This is a high-privilege operation by design.

---

## 9. Stage 7 — Security Gate

**Goal:** Act as the cryptographic privacy boundary. Nothing reaches the LLM unless it passes all five checks and is HMAC-signed.

### `gate/gate.py`

**Public interface:** `process(blocks, doc_id, vendor_id, assessment_id, doc_type, raw_values_for_check) -> GateApprovedPayload`

**The gate is fail-closed: any failure raises `GateViolation` and no payload is produced.**

The five steps:

**Step 1 — Re-scan:** Runs an independent Presidio instance (pattern-only, no spaCy) over every block. This is separate from Stage 2's detector — deliberate redundancy. If PII is found:
- Attempts emergency re-sanitization (`_auto_sanitize_residual`)
- Re-scans again
- If still found → `GateViolation` + quarantine

**Step 2 — Vault Leak Check:** For every known raw value (retrieved from the vault), checks that it does not appear verbatim or in normalised form (strip spaces/hyphens, lowercase) in any sanitized block's text. If found → `GateViolation`.

**Step 3 — Token Grammar Validation:** Scans for `<<...>>` and `[REDACTED:...]` patterns and validates them against 9 allowed grammar patterns. Detects partial/truncated redactions. Malformed placeholders → `GateViolation`.

**Step 4 — Entropy Check:** For every word ≥ 20 chars, computes `max_window_entropy`. If entropy > 4.5 bits → `GateViolation` (prevents API keys or private key material from slipping through in a form the redactor didn't recognise).

**Step 5 — HMAC Sign:** Signs the `GateApprovedPayload` using `gate/signing.py`.

Audit events are emitted for both quarantine and pass outcomes.

---

### `gate/signing.py`

- `sign_payload(payload, key) -> str` — computes HMAC-SHA256 over `payload.canonical_bytes()` (deterministic JSON, sorted keys, no `signature` field)
- `attach_signature(payload) -> GateApprovedPayload` — returns a copy with `signature` set
- `verify_signature(payload, key) -> bool` — constant-time HMAC verification

---

### `gate/verifier.py`

- `verify_gate_approved(payload) -> None` — the entry guard for the AI stage. Raises `SignatureError` if signature is empty or invalid.

This is both a type-system guard (only `GateApprovedPayload` objects have a `signature` field) and a runtime cryptographic guard. There is no way to bypass it short of knowing the signing key.

---

## 10. Stage 8 — AI Risk Analysis

**Goal:** Have a local LLM analyze the sanitized, signed text for security and privacy risks.

### `ai/analyzer.py`

**Public interface:** `async analyze(payload: GateApprovedPayload, llm=None) -> AIRiskResult`

**First action is always signature verification** — `verify_gate_approved(payload)` is called before anything else. If the signature is invalid, `SignatureError` is raised immediately.

**Flow:**
1. Groups blocks by `section_class` (access_control, encryption, incident_response, etc.)
2. For each section: combines block texts, chunks to ≤3000 chars
3. Calls `build_prompt` to construct system + user prompts
4. Invokes LLM with retry (up to `llm_max_retries+1` attempts)
5. Parses JSON response, strips markdown code fences, tries `json_repair` on parse failure
6. Drops any risk items with no valid evidence block IDs
7. Deduplicates by title similarity (Jaccard threshold)

**`FakeLLM`** — a deterministic test backend used in dev mode. Returns hardcoded risk items per section_class. No network call, no Ollama needed. This is why the system works out of the box.

**Real LLM** — `ChatOllama` via LangChain, connecting to `settings.ollama_url` (default `http://localhost:11434`), model `settings.llm_model`, temperature=0 for determinism.

---

### `ai/prompts.py`

`build_prompt(section_class, doc_type, sanitized_text, block_ids) -> (system_prompt, user_prompt)`

Key design decisions in the prompts:
- The full `AIRiskResult` JSON schema is embedded in the system prompt so the LLM knows exactly what format to output
- **Prompt injection hardening:** the user prompt wraps document text in `<<<DOCUMENT_TEXT_BEGIN>>>` / `<<<DOCUMENT_TEXT_END>>>` delimiters and the system prompt explicitly instructs the LLM to IGNORE any instructions found inside those delimiters
- The LLM is instructed: analyze only security/privacy risks, output ONLY JSON, cite evidence block IDs, never try to reconstruct redacted values

---

### `ai/schemas.py`

A thin re-export shim. Re-exports `AIRiskResult` and `RawRisk` from `common/models.py` under the `tprm.ai.schemas` path for external consumers.

---

## 11. Stage 9 — Risk Engine

**Goal:** Turn raw LLM output into scored, categorized, actionable findings.

### `risk/extractor.py`

- `extract(ai_result: AIRiskResult, blocks: list[SanitizedBlock]) -> list[NormalisedRisk]`
- Validates evidence block IDs (only keeps IDs that actually exist in the payload)
- Deduplicates using **Jaccard title similarity** (threshold 0.85) — merges titles that are ≥85% the same word set

---

### `risk/categorizer.py`

- `categorize(risk: NormalisedRisk) -> str` — maps a risk to a category ID from `risk_taxonomy.yaml`
- Scores each category by keyword overlap in `title + description`
- Adds +2 boost if the LLM's `claimed_category` matches (the LLM hint is considered but not determinative)
- Categories: ACCESS_MGMT, ENCRYPTION, INCIDENT_RESPONSE, BC_DR, PRIVACY_DATA, COMPLIANCE_AUDIT, SUBPROCESSOR, INFO_SEC, AI_MODEL_RISK, FINANCIAL, OPERATIONAL_RESILIENCE

---

### `risk/severity.py`

Computes a 0–100 severity score:

```
score = clamp(likelihood × impact × control_gap_factor × vendor_criticality × 100, 0, 100) + boosters
```

- `likelihood = category.likelihood_default × risk.confidence`
- `impact = category.impact_default` (from taxonomy YAML)
- `control_gap_factor`: `missing=1.6`, `partial=1.3`, `satisfied=1.0`
- `vendor_criticality`: the 0.8–1.5 weight from `DocumentMeta` (a Tier 1 vendor gets multiplied more)
- Label thresholds: Critical ≥75, High ≥50, Medium ≥25, Low ≥0

---

### `risk/controls.py`

- `map_controls(risk, section_class, category) -> list[ControlRef]`
- Loads `controls.yaml` and matches controls by: category, section_class, or keyword overlap
- `_assess_gap_status` heuristic: words like "missing", "gap", "not configured" → `missing`; "implemented", "enforced" → `partial`
- Returns up to 5 most relevant controls with framework references (e.g. ISO27001 A.5.15, SOC2 CC6.1)

---

### `risk/recommender.py`

- `recommend(finding: Finding) -> str` — generates a deterministic remediation recommendation
- Uses hardcoded templates keyed by `risk_category` — NOT an LLM call (deterministic and auditable)
- Appends compact control framework guidance: `"ISO27001 A.5.15 (Identity Management); SOC2 CC6.1 (Logical Access)"`

---

### Finding Description Builder (in `orchestrator.py`)

`_build_explicit_description(...)` constructs plain-English finding descriptions that tell the user exactly:
1. **Where** in the document the issue was found (using the deepest non-generic section heading)
2. **What** was found (e.g. "an API key or secret credential")
3. **Why** it's a problem (a 2-3 sentence explanation specific to that entity type)
4. **What to ask the vendor to do** (a concrete action)

Example output: *"In the 'Access Controls' section of this document, we found an API key or secret credential. API keys and secrets provide direct programmatic access to systems or cloud services. If exposed, an attacker can immediately use them to access your infrastructure. Ask the vendor to immediately rotate this credential and confirm it has been removed from all shared documents and version control history."*

---

## 12. Stages 10 & 11 — Workflow + OneTrust

### `workflow/state_machine.py`

Explicit allowed-transition state machine for findings:

```
Draft → InReview → RemediationRequested → RemediationInProgress → Verified → Accepted
                └→ Escalated ─────────────────────────────────────────────→ Rejected
```

- `transition(finding_id, to_status, actor_id, reason)` validates the transition is allowed, records a `WorkflowTransition`, stores the new state
- `history(finding_id)` returns the full transition log
- `InvalidTransition` is raised for illegal transitions

---

### `workflow/escalation.py`

- `check_escalation(finding, state_machine) -> EscalationRecord | None`
- **Critical findings** → immediately transitions to `Escalated`, routed to `ciso` queue (if `critical_immediate_escalation=True` in workflow YAML)
- **High findings past SLA** (default 30 days in Draft/InReview) → transitions to `Escalated`, routed to `risk_manager`

---

### `workflow/approval.py`

- `approve(finding, approver_id, decision, reason, state_machine)` — enforces **creator/approver separation** for High/Critical findings. The person who created the finding cannot approve it.
- `create_risk_acceptance(finding, accepted_by, justification, expiry_date)` — requires an expiry date and justification ≥ 50 characters (prevents lazy rubber-stamping)

---

### `onetrust/` — OneTrust Integration

**Why it exists:** OneTrust is a GRC (Governance, Risk & Compliance) platform where compliance teams track vendor risks. The integration pushes findings there so they flow into existing review workflows without requiring compliance teams to use a new tool.

**What gets pushed:**
- Vendor record (upsert)
- Assessment record tied to that vendor
- All findings (category, severity, score, recommendation)
- Workflow status

**Components:**
- `client.py` — `HttpOneTrustClient` with OAuth2 client credentials, exponential backoff retry, rate-limit handling
- `mock.py` — `MockOneTrustClient` (used everywhere in dev — all calls are no-ops that return fake IDs)
- `mapper.py` — `map_finding_to_onetrust(finding)` — maps `Finding` fields to OneTrust API payload. Field mapping is configurable in `config/onetrust_mapping.yaml`. Always adds `idempotencyKey` (deterministic UUID5).
- `base.py` — abstract base class `OneTrustClient` with the four methods: `upsert_vendor`, `create_assessment`, `push_findings`, `update_status`

**Current state:** The orchestrator always uses `MockOneTrustClient`. The real `HttpOneTrustClient` requires `TPRM_ONETRUST_ADAPTER=http` and valid OAuth2 credentials to activate.

---

## 13. API Layer

### `api/main.py`

FastAPI application factory. `create_app() -> FastAPI`:
- Mounts `/static` for UI assets
- Serves `ui/templates/index.html` at root `/`
- Registers all routes under `/api/v1`
- Exception handlers: `UnsupportedFormat → 415`, `GateViolation → 422` (detail hidden), `SignatureError → 403`, `TPRMError → 500` (type name only — no internal detail leaked)

---

### `api/routes.py`

All endpoints are protected by `X-API-Key` header checked against `settings.api_key`.

| Endpoint | What it does |
|---|---|
| `GET /api/v1/dashboard` | Aggregate stats: totals, high/critical findings, quarantine count, recent assessments, recent audit events |
| `GET /api/v1/assessments` | List all assessments |
| `POST /api/v1/assessments` | Upload a vendor document (multipart form), runs the full pipeline, returns `assessment_id` + sensitivity + finding count |
| `GET /api/v1/assessments/{id}` | Full assessment summary including gate report |
| `GET /api/v1/assessments/{id}/findings` | Detailed finding list including controls, recommendations, entity types found |
| `POST /api/v1/assessments/{id}/transition` | Trigger a workflow state transition |
| `GET /api/v1/gate/decisions` | All gate decision records |
| `GET /api/v1/audit` | All audit events across all documents |
| `GET /api/v1/audit/{doc_id}` | Per-document audit trail |
| `GET /api/v1/findings` | All findings across all assessments, sorted by score |
| `GET /api/v1/healthz` | Liveness probe |

**Note:** All storage is in-memory (`_assessments`, `_state_machines` dicts). Production would replace this with PostgreSQL.

---

## 14. CLI

### `cli.py`

Three commands via Typer:

```bash
# Run a full assessment
tprm run <file.pdf> --vendor acme-corp [--fake-llm] [--json]

# Explain a policy decision for a given entity type
tprm policy-explain --entity-type API_KEY --section-class access_control

# Verify the HMAC signature of a saved gate payload
tprm gate-verify <payload.json>
```

`tprm run` prints a formatted table of findings with severity, category, score, and a timing breakdown per pipeline stage.

---

## 15. Orchestrator — The Conductor

### `orchestrator.py`

**Public interface:** `async run_assessment(file_path, vendor_id, assessment_id, llm, use_fake_llm) -> AssessmentResult`

This is the only place all 11 stages are called in sequence. It:
- Generates an `assessment_id` UUID if not provided (for idempotency)
- Times each stage independently (`stage_timings` dict)
- Emits an audit event after each stage
- Handles `GateViolation` (re-raises after logging quarantine)
- Builds the `_build_explicit_description` for each finding (the human-readable section-aware description)
- Runs workflow escalation checks
- Pushes to OneTrust (mock by default)
- Returns `AssessmentResult`

The orchestrator is the only module that imports from all stages. All other modules only import from `common/` and modules at the same or lower level in the pipeline.

---

## 16. Security Guarantees Built Into the Architecture

These are not just good practices — they are structurally enforced:

| Guarantee | How it's enforced |
|---|---|
| PII text never appears in logs | `__repr__` on `Block`, `PIIEntity`, `SanitizedBlock` all omit `.text`. Logging functions use counts only. |
| PII text never reaches the LLM | The only input to `ai/analyzer.py` is `GateApprovedPayload`. There is no other path. |
| Gate payload can't be forged | `verify_gate_approved` raises `SignatureError` on any tampered or unsigned payload. First action in `analyze()`. |
| Independent re-scan | The gate uses a separate Presidio instance (not the Stage 2 instance) for its re-scan. Two independent detectors must both fail to let PII through. |
| Vault raw values never cross the boundary | Gate uses `lookup_raw_values` only to check that they do NOT appear — values are decrypted, checked, and discarded. They never enter `GateApprovedPayload`. |
| Tokenization is reversible only by design | `detokenize()` requires `TPRM_ALLOW_DETOKENIZE=true` env var AND a documented reason. |
| Audit log is tamper-evident | Hash-chained: changing any event breaks all subsequent hashes. `verify_chain()` can detect tampering. |
| High/Critical approvals require separation | `approval.py` raises `ApprovalViolation` if `approver_id == creator_id` for High or Critical findings. |
| Fail-closed everywhere | `GateViolation`, `SanitizationError`, and `sensitivity/scorer.py`'s route function all default to the most restrictive/secure path on any exception. |

---

## 17. Config Files

All in `tprm/config/`:

| File | What it controls |
|---|---|
| `policy.yaml` | PII recognizer confidence thresholds per entity type; section sensitivity floors; gate entropy threshold; file size / page count limits |
| `risk_taxonomy.yaml` | Risk categories with `likelihood_default` and `impact_default` weights; severity label thresholds (Critical ≥ 75, High ≥ 50, etc.); audit booster values |
| `controls.yaml` | Framework control mappings: each control has `id`, `framework`, `ref`, `name`, `categories`, `section_classes`, `keywords` |
| `workflow.yaml` | Allowed state transitions; SLA days per severity; escalation config (critical_immediate, high_past_sla) |
