---
inclusion: always
---

# Product Steering: Privacy-Preserving Vendor Risk (TPRM) Pipeline

## Purpose

This system automates third-party risk management (TPRM) assessments of vendor-submitted documents (PDF, DOCX, XLSX). It extracts PII, classifies sensitivity, sanitizes data, performs AI-assisted risk analysis via a local LLM, and pushes structured findings to OneTrust TPRM — all without raw PII ever leaving the private processing zone.

## Core Product Promise

> **The Security Gate is an architectural guarantee, not a configuration option.**
> No raw Personally Identifiable Information, credentials, key material, or RESTRICTED-level data ever crosses the Security Gate boundary. This is enforced at the data plane by cryptographic signing (HMAC-SHA256) and independent re-scanning, not by policy flags or runtime switches.

## The Security Gate Invariant

1. Every payload that exits the private zone is signed with `GateApprovedPayload.signature`.
2. The AI analysis stage verifies this signature on entry. An unsigned or tampered payload raises `SignatureError` immediately — it is a type-system and runtime impossibility to pass a raw `Document` to the AI stage.
3. Any failure, exception, or ambiguity in the private zone causes the pipeline to **fail closed**: the affected data is treated as `RESTRICTED` and is either sanitized or quarantined. There is no "best effort" pass-through.
4. The audit log is append-only and hash-chained so any tampering is detectable.

## What This System Is Not

- It is not a general-purpose document processing API.
- It does not make risk decisions using only AI — the policy engine, severity scoring, and control mapping are fully deterministic and rule-based.
- It does not contact external services from the private processing zone.
- It does not store or log raw PII outside the encrypted token vault.

## Primary Users

| Role | What They Care About |
|---|---|
| Risk Analyst | Accurate, auditable findings; clear remediation steps |
| Risk Manager | SLA compliance; escalation visibility; workflow control |
| CISO | Critical escalations; risk-acceptance governance |
| Compliance / DPO | Zero PII leakage; verifiable audit chain |
| Platform / SRE | Determinism, testability, operational simplicity |

## Success Criteria

- `make demo` runs a vendor PDF end-to-end to a mock OneTrust outbox payload with zero errors.
- The leak-canary test suite passes with zero raw or normalised canary values in any downstream artifact.
- Every architecture box from the spec maps to exactly one Python package.
- `ruff`, `mypy --strict`, and `pytest` (≥ 85 % coverage; 100 % on `gate/` and `sanitize/`) all pass.
