"""Gate verifier — entry guard for the AI analysis stage.

ai/analyzer.py calls verify_gate_approved() as its first action.
Any unsigned or tampered payload raises SignatureError immediately.
"""

from __future__ import annotations

from tprm.common.errors import SignatureError
from tprm.common.models import GateApprovedPayload
from tprm.gate.signing import verify_signature


def verify_gate_approved(
    payload: GateApprovedPayload,
    key: bytes | None = None,
) -> None:
    """Verify the HMAC signature of a GateApprovedPayload.

    Raises:
        SignatureError: If the signature is missing, invalid, or the payload
                        has been tampered with.

    This is the type-system + runtime guard: only GateApprovedPayload objects
    can be passed here. A raw Document has no signature field.
    """
    if not payload.signature:
        raise SignatureError(
            "GateApprovedPayload is missing a signature. "
            "All payloads must be signed by the Security Gate before AI analysis."
        )

    if not verify_signature(payload, key):
        raise SignatureError(
            "GateApprovedPayload signature verification failed. "
            "The payload may have been tampered with or was not produced by the Security Gate."
        )
