"""Document and section classifier using keyword rules + embedding similarity.

Falls back to keyword-only classification when sentence-transformers is unavailable.
Classification confidence below threshold → 'unknown' + CONFIDENTIAL floor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from tprm.common.logging import get_logger

log = get_logger(__name__)

_CONFIDENCE_THRESHOLD = 0.60

# ── Document type keyword rules ───────────────────────────────────────────────

_DOC_TYPE_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("soc2_report", re.compile(
        r"\b(?:SOC\s*2|service organization controls|trust service criteria|type\s*II?\b.*audit)\b",
        re.IGNORECASE,
    )),
    ("iso_cert", re.compile(
        r"\b(?:ISO\s*27001|ISMS|information security management system|certificate of compliance)\b",
        re.IGNORECASE,
    )),
    ("pentest_report", re.compile(
        r"\b(?:penetration test|pentest|pen test|ethical hack|vulnerability assessment)\b",
        re.IGNORECASE,
    )),
    ("security_questionnaire", re.compile(
        r"\b(?:security questionnaire|vendor assessment questionnaire|VSAQ|SIG questionnaire)\b",
        re.IGNORECASE,
    )),
    ("dpa", re.compile(
        r"\b(?:data processing agreement|DPA|data processor|controller.*processor)\b",
        re.IGNORECASE,
    )),
    ("msa", re.compile(
        r"\b(?:master service agreement|MSA|services agreement|statement of work|SOW)\b",
        re.IGNORECASE,
    )),
    ("sla", re.compile(
        r"\b(?:service level agreement|SLA|uptime guarantee|availability commitment)\b",
        re.IGNORECASE,
    )),
    ("architecture_doc", re.compile(
        r"\b(?:architecture diagram|system design|technical design|infrastructure diagram|network diagram)\b",
        re.IGNORECASE,
    )),
    ("bcp_dr_plan", re.compile(
        r"\b(?:business continuity|BCP|disaster recovery|DR plan|RTO|RPO|failover plan)\b",
        re.IGNORECASE,
    )),
]

# ── Section class keyword rules ───────────────────────────────────────────────

_SECTION_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("access_control", re.compile(
        r"\b(?:access control|authentication|MFA|multi.factor|IAM|privilege|least privilege|"
        r"user management|identity|role.based|RBAC|SSO)\b",
        re.IGNORECASE,
    )),
    ("encryption", re.compile(
        r"\b(?:encrypt|TLS|SSL|AES|RSA|cryptograph|key management|KMS|HSM|certificate|"
        r"data at rest|data in transit|cipher)\b",
        re.IGNORECASE,
    )),
    ("incident_response", re.compile(
        r"\b(?:incident response|IR plan|CSIRT|breach|notification|SIEM|forensics|containment|"
        r"detection|eradication|playbook)\b",
        re.IGNORECASE,
    )),
    ("bc_dr", re.compile(
        r"\b(?:business continuity|disaster recovery|BCP|DR|RTO|RPO|backup|restore|failover|"
        r"redundancy|recovery time)\b",
        re.IGNORECASE,
    )),
    ("subprocessors", re.compile(
        r"\b(?:subprocessor|sub.processor|fourth.party|supply chain|outsourc|subcontract)\b",
        re.IGNORECASE,
    )),
    ("data_retention", re.compile(
        r"\b(?:data retention|retention policy|data deletion|erasure|right to be forgotten|"
        r"purge|archive|data lifecycle)\b",
        re.IGNORECASE,
    )),
    ("audit_scope", re.compile(
        r"\b(?:audit scope|in scope|out of scope|audit period|audit opinion|audited by|"
        r"scope of examination|covered services)\b",
        re.IGNORECASE,
    )),
    ("exceptions_qualifications", re.compile(
        r"\b(?:exception|qualification|qualified opinion|deviation|finding|deficiency|"
        r"material weakness|adverse opinion)\b",
        re.IGNORECASE,
    )),
]


@dataclass
class ClassificationResult:
    label: str
    confidence: float


def classify_doc(doc_text: str) -> ClassificationResult:
    """Classify the document type based on a sample of its text.

    Returns (label, confidence). If confidence < threshold → label='unknown'.
    """
    # Keyword rules first (cheap, deterministic)
    for label, pattern in _DOC_TYPE_RULES:
        if pattern.search(doc_text):
            return ClassificationResult(label=label, confidence=0.85)

    # Try embedding-based classification if available
    embedding_result = _classify_with_embeddings(doc_text, _DOC_TYPE_RULES)
    if embedding_result and embedding_result.confidence >= _CONFIDENCE_THRESHOLD:
        return embedding_result

    return ClassificationResult(label="other", confidence=0.40)


def classify_section(block_text: str) -> ClassificationResult:
    """Classify the section class for a block.

    Returns (label, confidence). If confidence < threshold → label='unknown'.
    """
    for label, pattern in _SECTION_RULES:
        if pattern.search(block_text):
            return ClassificationResult(label=label, confidence=0.85)

    # Try embedding-based classification
    embedding_result = _classify_with_embeddings(block_text, _SECTION_RULES)
    if embedding_result and embedding_result.confidence >= _CONFIDENCE_THRESHOLD:
        return embedding_result

    return ClassificationResult(label="unknown", confidence=0.30)


def _classify_with_embeddings(
    text: str,
    rules: list[tuple[str, re.Pattern[str]]],
) -> ClassificationResult | None:
    """Attempt embedding-based classification (requires sentence-transformers)."""
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]
        import numpy as np  # type: ignore[import-untyped]
    except ImportError:
        return None

    try:
        model = _get_embedding_model()
        if model is None:
            return None

        labels = [label for label, _ in rules]
        prototypes = _get_prototypes(labels)
        if not prototypes:
            return None

        text_embedding = model.encode([text[:512]])[0]

        best_label = "unknown"
        best_score = 0.0

        for label, prototype_embedding in prototypes.items():
            # Cosine similarity
            dot = float(np.dot(text_embedding, prototype_embedding))
            norm = float(np.linalg.norm(text_embedding) * np.linalg.norm(prototype_embedding))
            similarity = dot / norm if norm > 0 else 0.0
            if similarity > best_score:
                best_score = similarity
                best_label = label

        if best_score >= _CONFIDENCE_THRESHOLD:
            return ClassificationResult(label=best_label, confidence=best_score)
    except Exception as exc:
        log.debug("embedding_classification_failed", error=str(exc))

    return None


_EMBEDDING_MODEL: Any = None
_EMBEDDING_MODEL_LOADED = False

_PROTOTYPE_TEXTS: dict[str, str] = {
    "soc2_report": "SOC 2 Type II report service organization controls trust service criteria",
    "iso_cert": "ISO 27001 certificate information security management system ISMS",
    "pentest_report": "penetration testing report vulnerability assessment ethical hacking findings",
    "security_questionnaire": "security questionnaire vendor assessment third party risk controls",
    "dpa": "data processing agreement DPA GDPR data controller processor personal data",
    "msa": "master service agreement professional services statement of work terms conditions",
    "sla": "service level agreement uptime availability response time SLA metrics",
    "architecture_doc": "system architecture diagram infrastructure network design components",
    "bcp_dr_plan": "business continuity disaster recovery BCP RTO RPO failover backup",
    "access_control": "access control user management authentication MFA privilege IAM RBAC",
    "encryption": "encryption TLS AES key management data at rest in transit certificate",
    "incident_response": "incident response IR plan breach notification CSIRT SIEM forensics",
    "bc_dr": "business continuity disaster recovery backup restore failover redundancy",
    "subprocessors": "subprocessors fourth party supply chain outsourcing subcontractors",
    "data_retention": "data retention deletion erasure right to be forgotten archive lifecycle",
    "audit_scope": "audit scope in scope covered services audit period examination",
    "exceptions_qualifications": "exception qualification qualified opinion finding deficiency",
}

_PROTOTYPES_CACHE: dict[str, Any] = {}


def _get_embedding_model() -> Any:
    global _EMBEDDING_MODEL, _EMBEDDING_MODEL_LOADED  # noqa: PLW0603
    if _EMBEDDING_MODEL_LOADED:
        return _EMBEDDING_MODEL
    _EMBEDDING_MODEL_LOADED = True
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]

        _EMBEDDING_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    except Exception as exc:
        log.warning("embedding_model_load_failed", error=str(exc))
        _EMBEDDING_MODEL = None
    return _EMBEDDING_MODEL


def _get_prototypes(labels: list[str]) -> dict[str, Any]:
    global _PROTOTYPES_CACHE  # noqa: PLW0603
    if _PROTOTYPES_CACHE:
        return {k: v for k, v in _PROTOTYPES_CACHE.items() if k in labels}

    model = _get_embedding_model()
    if model is None:
        return {}

    try:
        for label, text in _PROTOTYPE_TEXTS.items():
            if label in labels:
                _PROTOTYPES_CACHE[label] = model.encode([text])[0]
    except Exception:
        pass

    return {k: v for k, v in _PROTOTYPES_CACHE.items() if k in labels}
