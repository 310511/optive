"""Custom exception hierarchy for the TPRM pipeline.

All exceptions avoid including raw PII values in their messages.
Reference entities by type + block_id, never by content.
"""

from __future__ import annotations


class TPRMError(Exception):
    """Base exception for all TPRM pipeline errors."""


# ── Ingestion ─────────────────────────────────────────────────────────────────


class UnsupportedFormat(TPRMError):
    """Raised when the submitted file format is not supported (not PDF/DOCX/XLSX)."""


class FileTooLarge(TPRMError):
    """Raised when the submitted file exceeds the configured size limit."""


class TooManyPages(TPRMError):
    """Raised when the document exceeds the configured page limit."""


class ZipBombDetected(TPRMError):
    """Raised when decompression ratio exceeds the configured safety threshold."""


class IngestionError(TPRMError):
    """General parsing or OCR failure during document ingestion."""


# ── PII / NLP ─────────────────────────────────────────────────────────────────


class PIIDetectionError(TPRMError):
    """Raised when the PII detection stage encounters an unrecoverable error."""


class NLPError(TPRMError):
    """Raised when the NLP stage encounters an unrecoverable error."""


# ── Policy ────────────────────────────────────────────────────────────────────


class PolicyConfigError(TPRMError):
    """Raised when the policy YAML is invalid or missing required fields."""


class PolicyDecisionError(TPRMError):
    """Raised when a policy decision cannot be made (should fail closed → RESTRICTED)."""


# ── Sanitization ──────────────────────────────────────────────────────────────


class SanitizationError(TPRMError):
    """Raised when sanitization of a block fails."""


class VaultError(TPRMError):
    """Raised when the token vault encounters a storage or retrieval error."""


class DetokenizationDisabled(TPRMError):
    """Raised when detokenization is attempted but the policy flag is not set."""


# ── Security Gate ─────────────────────────────────────────────────────────────


class GateViolation(TPRMError):
    """Raised when the Security Gate detects that data should not cross the boundary.

    This is the most critical exception — it causes the pipeline to fail closed.
    The message MUST NOT contain raw PII values; use entity types and counts only.
    """


class SignatureError(TPRMError):
    """Raised when a GateApprovedPayload has an invalid or missing HMAC signature."""


class EntropyViolation(TPRMError):
    """Raised when a high-entropy string is detected in gate output."""


class MalformedPlaceholder(TPRMError):
    """Raised when a token or redaction placeholder fails grammar validation."""


# ── AI Analysis ───────────────────────────────────────────────────────────────


class LLMError(TPRMError):
    """Raised when the LLM call fails after all retries."""


class LLMParseError(TPRMError):
    """Raised when the LLM output cannot be parsed into AIRiskResult after retries."""


# ── Risk Engine ───────────────────────────────────────────────────────────────


class RiskEngineError(TPRMError):
    """General risk engine processing error."""


# ── Workflow ──────────────────────────────────────────────────────────────────


class InvalidTransition(TPRMError):
    """Raised when a requested workflow state transition is not permitted."""


class ApprovalViolation(TPRMError):
    """Raised when approver == creator for a High/Critical finding."""


class RiskAcceptanceError(TPRMError):
    """Raised when a risk acceptance record is missing required fields."""


# ── OneTrust ──────────────────────────────────────────────────────────────────


class PayloadViolation(TPRMError):
    """Raised when the OneTrust outbox payload validator detects raw PII."""


class OneTrustError(TPRMError):
    """Raised when the OneTrust API call fails after all retries."""


# ── Orchestrator ──────────────────────────────────────────────────────────────


class CheckpointError(TPRMError):
    """Raised when a pipeline checkpoint cannot be read or written."""


class DuplicateAssessment(TPRMError):
    """Raised when the same (vendor_id, sha256) is submitted and resumption fails."""
