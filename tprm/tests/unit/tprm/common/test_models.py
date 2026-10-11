"""Unit tests for common/models.py."""

from __future__ import annotations

import pytest

from tprm.common.models import (
    AssessmentResult,
    Block,
    ClassifiedBlock,
    Document,
    DocumentMeta,
    GateApprovedPayload,
    GateReport,
    NLPContext,
    PIIEntity,
    PolicyDecision,
    SanitizedBlock,
    SensitivityLevel,
    Transform,
)


class TestSensitivityLevel:
    def test_ordering(self) -> None:
        assert SensitivityLevel.PUBLIC < SensitivityLevel.INTERNAL
        assert SensitivityLevel.INTERNAL < SensitivityLevel.CONFIDENTIAL
        assert SensitivityLevel.CONFIDENTIAL < SensitivityLevel.RESTRICTED

    def test_max(self) -> None:
        levels = [SensitivityLevel.PUBLIC, SensitivityLevel.CONFIDENTIAL, SensitivityLevel.INTERNAL]
        assert max(levels) == SensitivityLevel.CONFIDENTIAL

    def test_from_str(self) -> None:
        assert SensitivityLevel.from_str("RESTRICTED") == SensitivityLevel.RESTRICTED
        assert SensitivityLevel.from_str("public") == SensitivityLevel.PUBLIC

    def test_from_str_invalid(self) -> None:
        with pytest.raises(KeyError):
            SensitivityLevel.from_str("UNKNOWN")

    def test_ge_comparison(self) -> None:
        assert SensitivityLevel.CONFIDENTIAL >= SensitivityLevel.CONFIDENTIAL
        assert SensitivityLevel.RESTRICTED >= SensitivityLevel.CONFIDENTIAL
        assert not (SensitivityLevel.INTERNAL >= SensitivityLevel.CONFIDENTIAL)


class TestBlock:
    def test_repr_excludes_text(self) -> None:
        block = Block(doc_id="d1", page=1, text="john.doe@example.com secret content")
        r = repr(block)
        assert "john.doe@example.com" not in r
        assert "secret" not in r
        assert "Block(" in r

    def test_default_source(self) -> None:
        block = Block(doc_id="d1", page=1, text="hello")
        assert block.source == "native"


class TestDocument:
    def test_valid(self) -> None:
        meta = DocumentMeta(file_size_bytes=1024, page_count=5, doc_format="pdf")
        doc = Document(
            vendor_id="vendor-1",
            filename="test.pdf",
            sha256="a" * 64,
            meta=meta,
        )
        assert doc.vendor_id == "vendor-1"

    def test_invalid_sha256(self) -> None:
        meta = DocumentMeta(file_size_bytes=1024, page_count=5, doc_format="pdf")
        with pytest.raises(ValueError, match="sha256"):
            Document(
                vendor_id="v1",
                filename="test.pdf",
                sha256="not_a_valid_sha256",
                meta=meta,
            )

    def test_repr_excludes_blocks_content(self) -> None:
        meta = DocumentMeta(file_size_bytes=100, page_count=1, doc_format="pdf")
        doc = Document(vendor_id="v1", filename="f.pdf", sha256="b" * 64, meta=meta)
        r = repr(doc)
        assert "filename=" in r
        assert "blocks=0" in r


class TestPIIEntity:
    def test_valid_span(self) -> None:
        e = PIIEntity(
            block_id="b1",
            start=0,
            end=10,
            entity_type="EMAIL_ADDRESS",
            text="x@x.com",
            score=0.9,
            recognizer="email",
        )
        assert e.start < e.end

    def test_invalid_span(self) -> None:
        with pytest.raises(ValueError, match="start"):
            PIIEntity(
                block_id="b1",
                start=10,
                end=5,
                entity_type="EMAIL_ADDRESS",
                text="x",
                score=0.9,
                recognizer="email",
            )

    def test_repr_excludes_text(self) -> None:
        e = PIIEntity(
            block_id="b1",
            start=0,
            end=10,
            entity_type="EMAIL_ADDRESS",
            text="secret@corp.com",
            score=0.9,
            recognizer="email",
        )
        r = repr(e)
        assert "secret@corp.com" not in r
        assert "EMAIL_ADDRESS" in r


class TestClassifiedBlock:
    def _make_block(self, text: str = "hello") -> Block:
        return Block(doc_id="d1", page=1, text=text)

    def test_block_level_max_of_decisions(self) -> None:
        block = self._make_block()
        ctx = NLPContext(
            block_id=block.id,
            doc_type="soc2_report",
            section_class="access_control",
            section_sensitivity_floor=SensitivityLevel.INTERNAL,
        )
        decisions = [
            PolicyDecision(
                entity_ref="b:0-5",
                entity_type="EMAIL_ADDRESS",
                level=SensitivityLevel.CONFIDENTIAL,
                action="tokenize",
                rule_id="R099",
                rationale="test",
            ),
            PolicyDecision(
                entity_ref="b:5-10",
                entity_type="PERSON",
                level=SensitivityLevel.INTERNAL,
                action="keep",
                rule_id="R013",
                rationale="test",
            ),
        ]
        cb = ClassifiedBlock(block=block, ctx=ctx, decisions=decisions)
        assert cb.block_level == SensitivityLevel.CONFIDENTIAL

    def test_block_level_raised_by_floor(self) -> None:
        block = self._make_block()
        ctx = NLPContext(
            block_id=block.id,
            doc_type="dpa",
            section_class="unknown",
            section_sensitivity_floor=SensitivityLevel.CONFIDENTIAL,
        )
        decisions = [
            PolicyDecision(
                entity_ref="b:0-5",
                entity_type="ORG",
                level=SensitivityLevel.INTERNAL,
                action="keep",
                rule_id="R013",
                rationale="test",
            )
        ]
        cb = ClassifiedBlock(block=block, ctx=ctx, decisions=decisions)
        # Floor is CONFIDENTIAL, decision is INTERNAL → block_level should be CONFIDENTIAL
        assert cb.block_level >= SensitivityLevel.CONFIDENTIAL

    def test_block_level_never_lower_after_decisions(self) -> None:
        """Adding a PUBLIC decision to a block with RESTRICTED floor never lowers level."""
        block = self._make_block()
        ctx = NLPContext(
            block_id=block.id,
            doc_type="pentest_report",
            section_class="access_control",
            section_sensitivity_floor=SensitivityLevel.RESTRICTED,
        )
        decisions = [
            PolicyDecision(
                entity_ref="b:0-3",
                entity_type="ORG",
                level=SensitivityLevel.PUBLIC,
                action="keep",
                rule_id="R013",
                rationale="public org name",
            )
        ]
        cb = ClassifiedBlock(block=block, ctx=ctx, decisions=decisions)
        assert cb.block_level >= SensitivityLevel.RESTRICTED


class TestAuditEvent:
    def test_hash_deterministic(self) -> None:
        from tprm.common.models import AuditEvent

        e = AuditEvent(
            stage="pii",
            doc_id="d1",
            actor="system",
            action="detect",
            counts={"EMAIL": 3},
            prev_hash="abc",
        )
        h1 = e.compute_hash()
        h2 = e.compute_hash()
        assert h1 == h2

    def test_hash_changes_on_tamper(self) -> None:
        from tprm.common.models import AuditEvent

        e = AuditEvent(
            stage="pii",
            doc_id="d1",
            actor="system",
            action="detect",
            counts={"EMAIL": 3},
            prev_hash="abc",
        )
        original_hash = e.compute_hash()
        e.counts = {"EMAIL": 99}
        tampered_hash = e.compute_hash()
        assert original_hash != tampered_hash


class TestGateApprovedPayload:
    def test_canonical_bytes_exclude_signature(self) -> None:
        gate_report = GateReport(
            doc_id="d1",
            total_blocks=1,
            safe_path_blocks=1,
            sensitive_path_blocks=0,
            passed=True,
        )
        payload = GateApprovedPayload(
            doc_id="d1",
            vendor_id="v1",
            doc_type="soc2_report",
            blocks=[],
            gate_report=gate_report,
            signature="dummy",
        )
        canonical = payload.canonical_bytes()
        assert b"dummy" not in canonical
        assert b"d1" in canonical
