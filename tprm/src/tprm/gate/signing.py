"""Gate payload signing and verification.

HMAC-SHA256 over canonical JSON of GateApprovedPayload (excluding signature field).
Uses constant-time comparison to prevent timing attacks.
"""

from __future__ import annotations

from tprm.common.crypto import hmac_sign, hmac_verify, load_gate_signing_key
from tprm.common.errors import SignatureError
from tprm.common.models import GateApprovedPayload


def sign_payload(payload: GateApprovedPayload, key: bytes | None = None) -> str:
    """Compute HMAC-SHA256 signature over canonical payload bytes.

    Returns the hex digest string.
    """
    if key is None:
        key = load_gate_signing_key()
    return hmac_sign(payload.canonical_bytes(), key)


def verify_signature(payload: GateApprovedPayload, key: bytes | None = None) -> bool:
    """Return True if payload.signature is valid; False otherwise."""
    if key is None:
        try:
            key = load_gate_signing_key()
        except Exception:
            return False
    return hmac_verify(payload.canonical_bytes(), key, payload.signature)


def attach_signature(payload: GateApprovedPayload, key: bytes | None = None) -> GateApprovedPayload:
    """Return a new GateApprovedPayload with the signature field populated."""
    sig = sign_payload(payload, key)
    return payload.model_copy(update={"signature": sig})
