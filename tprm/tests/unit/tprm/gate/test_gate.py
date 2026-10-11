"""Unit tests for gate/ — signing, verifier, gate process."""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("TPRM_VAULT_KEY", "j5yCD74TW57pnqdPTzy_qHDrAjXX89hdQwdpM4Bf0l8=")
os.environ.setdefault("GATE_SIGNING_KEY", "test-gate-key")


@pytest.fixture(autouse=True)
def stub_gate_analyzer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent Presidio/spaCy loading during gate unit tests."""
    import tprm.gate.gate as gate_module

    gate_module.reset_gate_analyzer()
    # Inject a mock analyzer that returns no PII hits
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = []
    gate_module._GATE_ANALYZER = mock_analyzer
    gate_module._GATE_ANALYZER_LOADED = True


def _make_sanitized_block(block_id: str = "b1", text: str = "Encryption uses AES-256.") -> object:
    from tprm.common.models import SanitizedBlock
    return SanitizedBlock(
        block_id=block_id,
        doc_id="d1",
        section_path=["2. Encryption"],
        section_class="encryption",
        text_sanitized=text,
        applied=[],
    )


def _make_signed_payload() -> object:
    from tprm.common.models import GateApprovedPayload, GateReport
    from tprm.gate.signing import attach_signature

    gate_report = GateReport(
        doc_id="d1", total_blocks=1, safe_path_blocks=1,
        sensitive_path_blocks=0, passed=True,
    )
    payload = GateApprovedPayload(
        doc_id="d1", vendor_id="v1", doc_type="soc2_report",
        blocks=[_make_sanitized_block()],  # type: ignore[list-item]
        gate_report=gate_report,
        signature="",
    )
    return attach_signature(payload)


class TestSigning:
    def test_sign_and_verify(self) -> None:
        from tprm.gate.signing import attach_signature, verify_signature

        payload = _make_signed_payload()
        assert verify_signature(payload)  # type: ignore[arg-type]

    def test_tampered_payload_fails(self) -> None:
        from tprm.gate.signing import verify_signature

        payload = _make_signed_payload()
        # Tamper by modifying doc_id after signing
        from tprm.common.models import GateApprovedPayload
        assert isinstance(payload, GateApprovedPayload)
        tampered = payload.model_copy(update={"doc_id": "hacked"})
        assert not verify_signature(tampered)

    def test_empty_signature_fails(self) -> None:
        from tprm.gate.signing import verify_signature
        from tprm.common.models import GateApprovedPayload, GateReport

        gate_report = GateReport(doc_id="d1", total_blocks=0, safe_path_blocks=0,
                                 sensitive_path_blocks=0, passed=False)
        payload = GateApprovedPayload(
            doc_id="d1", vendor_id="v1", doc_type="other",
            blocks=[], gate_report=gate_report, signature="",
        )
        assert not verify_signature(payload)


class TestVerifier:
    def test_valid_payload_passes(self) -> None:
        from tprm.gate.verifier import verify_gate_approved

        payload = _make_signed_payload()
        verify_gate_approved(payload)  # type: ignore[arg-type] — should not raise

    def test_unsigned_payload_raises(self) -> None:
        from tprm.gate.verifier import verify_gate_approved
        from tprm.common.errors import SignatureError
        from tprm.common.models import GateApprovedPayload, GateReport

        gate_report = GateReport(doc_id="d1", total_blocks=0, safe_path_blocks=0,
                                 sensitive_path_blocks=0, passed=False)
        payload = GateApprovedPayload(
            doc_id="d1", vendor_id="v1", doc_type="other",
            blocks=[], gate_report=gate_report, signature="",
        )
        with pytest.raises(SignatureError):
            verify_gate_approved(payload)

    def test_tampered_payload_raises(self) -> None:
        from tprm.gate.verifier import verify_gate_approved
        from tprm.common.errors import SignatureError
        from tprm.common.models import GateApprovedPayload

        payload = _make_signed_payload()
        assert isinstance(payload, GateApprovedPayload)
        tampered = payload.model_copy(update={"doc_id": "injected"})
        with pytest.raises(SignatureError):
            verify_gate_approved(tampered)


class TestGateProcess:
    def test_clean_blocks_produce_signed_payload(self) -> None:
        from tprm.gate.gate import process

        blocks = [_make_sanitized_block(text="The vendor uses AES-256 encryption.")]  # type: ignore[list-item]
        payload = process(blocks, "d1", "v1", doc_type="soc2_report")  # type: ignore[arg-type]
        assert payload.gate_report.passed is True
        assert len(payload.signature) == 64

    def test_high_entropy_string_triggers_violation(self) -> None:
        from tprm.gate.gate import process
        from tprm.common.errors import GateViolation
        from tprm.common.crypto import max_window_entropy
        import base64, secrets

        # A full 44-char Fernet key has entropy > 4.5 across a 40-char window
        raw_fernet_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        assert max_window_entropy(raw_fernet_key, 40) > 4.5, "Fixture must have high entropy"

        blocks = [_make_sanitized_block(text=f"VaultKey={raw_fernet_key}")]  # type: ignore[list-item]
        with pytest.raises(GateViolation):
            process(blocks, "d1", "v1")  # type: ignore[arg-type]

    def test_raw_value_in_output_triggers_violation(self) -> None:
        from tprm.gate.gate import process
        from tprm.common.errors import GateViolation

        raw_email = "alice@company-internal.example.com"
        # Block still contains the raw email (not sanitized)
        blocks = [_make_sanitized_block(text=f"Contact: {raw_email}")]  # type: ignore[list-item]
        with pytest.raises(GateViolation):
            process(  # type: ignore[arg-type]
                blocks, "d1", "v1",
                raw_values_for_check=[raw_email],
            )

    def test_gate_signed_payload_verifiable(self) -> None:
        from tprm.gate.gate import process
        from tprm.gate.verifier import verify_gate_approved

        blocks = [_make_sanitized_block()]  # type: ignore[list-item]
        payload = process(blocks, "d1", "v1")  # type: ignore[arg-type]
        verify_gate_approved(payload)  # must not raise
