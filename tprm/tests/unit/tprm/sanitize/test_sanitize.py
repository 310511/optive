"""Unit tests for sanitize/ — redact, tokenize, generalize, vault, pipeline."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("TPRM_VAULT_KEY", "j5yCD74TW57pnqdPTzy_qHDrAjXX89hdQwdpM4Bf0l8=")
os.environ.setdefault("GATE_SIGNING_KEY", "test-gate-key")


class TestRedact:
    def test_single_span(self) -> None:
        from tprm.sanitize.redact import redact

        result = redact("Hello john.doe@corp.com world", [(6, 26, "EMAIL_ADDRESS")])
        assert "john.doe@corp.com" not in result
        assert "[REDACTED:EMAIL_ADDRESS]" in result

    def test_multiple_spans_right_to_left(self) -> None:
        from tprm.sanitize.redact import redact

        text = "Name: Alice Smith, SSN: 123-45-6789"
        spans = [(6, 17, "PERSON"), (24, 35, "US_SSN")]
        result = redact(text, spans)
        assert "Alice Smith" not in result
        assert "123-45-6789" not in result
        assert result.count("[REDACTED:") == 2

    def test_idempotent(self) -> None:
        from tprm.sanitize.redact import redact

        text = "[REDACTED:EMAIL_ADDRESS]"
        # Already a placeholder — applying again on a non-overlapping empty span
        result = redact(text, [])
        assert result == text

    def test_empty_spans(self) -> None:
        from tprm.sanitize.redact import redact

        text = "No PII here"
        assert redact(text, []) == text


class TestTokenize:
    def test_token_format(self) -> None:
        from tprm.sanitize.tokenize import tokenize

        text = "Email: alice@example.com end"
        spans = [(7, 24, "EMAIL_ADDRESS", "alice@example.com")]
        result_text, token_map = tokenize(text, spans, "test-salt")
        assert "alice@example.com" not in result_text
        assert len(token_map) == 1
        token = next(iter(token_map))
        assert token.startswith("<<EMAIL_ADDRESS_")
        assert token.endswith(">>")

    def test_determinism(self) -> None:
        from tprm.sanitize.tokenize import tokenize

        spans = [(0, 17, "EMAIL_ADDRESS", "alice@example.com")]
        t1, _ = tokenize("alice@example.com", spans, "salt-a")
        t2, _ = tokenize("alice@example.com", spans, "salt-a")
        assert t1 == t2

    def test_different_salts_different_tokens(self) -> None:
        from tprm.sanitize.tokenize import tokenize

        spans = [(0, 17, "EMAIL_ADDRESS", "alice@example.com")]
        t1, _ = tokenize("alice@example.com", spans, "salt-a")
        t2, _ = tokenize("alice@example.com", spans, "salt-b")
        assert t1 != t2

    def test_token_map_contains_raw_value(self) -> None:
        from tprm.sanitize.tokenize import tokenize

        spans = [(0, 17, "EMAIL_ADDRESS", "alice@example.com")]
        _, token_map = tokenize("alice@example.com", spans, "salt")
        assert "alice@example.com" in token_map.values()


class TestGeneralize:
    def test_internal_ip(self) -> None:
        from tprm.sanitize.generalize import generalize

        text = "Server at 10.0.1.42"
        spans = [(10, 19, "IP_ADDRESS", "10.0.1.42")]
        result = generalize(text, spans)
        assert "10.0.1.42" not in result
        assert "[INTERNAL_IP_RANGE]" in result

    def test_person_unknown_role(self) -> None:
        from tprm.sanitize.generalize import generalize

        text = "Contact: Alice Smith"
        spans = [(9, 20, "PERSON", "Alice Smith")]
        result = generalize(text, spans)
        assert "Alice Smith" not in result
        assert "[PERSON:UNKNOWN]" in result

    def test_person_with_role(self) -> None:
        from tprm.sanitize.generalize import generalize
        from tprm.common.models import Relation

        relations = [Relation(
            source_entity_id="b1:9-20",
            target_entity_id="role:ciso",
            relation_type="person_role",
            block_ids=["b1"],
        )]
        text = "Contact: Alice Smith"
        spans = [(9, 20, "PERSON", "Alice Smith")]
        result = generalize(text, spans, relations)
        assert "Alice Smith" not in result
        assert "[PERSON:CISO]" in result

    def test_internal_hostname(self) -> None:
        from tprm.sanitize.generalize import generalize

        text = "Host: db.prod.corp.internal"
        spans = [(6, 26, "INTERNAL_HOSTNAME", "db.prod.corp.internal")]
        result = generalize(text, spans)
        assert "db.prod.corp.internal" not in result
        assert "[HOST:" in result


class TestVault:
    def setup_method(self) -> None:
        from tprm.sanitize.vault import reset_vault
        reset_vault()

    def test_store_and_lookup(self) -> None:
        from tprm.sanitize.vault import get_vault

        vault = get_vault()
        vault.store("<<EMAIL_ADDRESS_abc12345>>", "alice@example.com", "EMAIL_ADDRESS", "assess-1")
        raw_values = vault.lookup_raw_values("assess-1")
        assert "alice@example.com" in raw_values

    def test_ciphertext_not_plaintext(self) -> None:
        from tprm.sanitize.vault import get_vault, TokenVault

        vault = TokenVault()
        vault.store("<<EMAIL_ADDRESS_abc12345>>", "secret-value", "EMAIL_ADDRESS", "assess-1")
        # Check internal store — ciphertext should not equal plaintext
        ciphertext = vault._store["assess-1"]["<<EMAIL_ADDRESS_abc12345>>"]
        assert b"secret-value" not in ciphertext

    def test_detokenize_disabled_by_default(self) -> None:
        from tprm.sanitize.vault import get_vault
        from tprm.common.errors import DetokenizationDisabled

        vault = get_vault()
        vault.store("<<T_abc12345>>", "raw", "EMAIL_ADDRESS", "assess-1")
        with pytest.raises(DetokenizationDisabled):
            vault.detokenize("<<T_abc12345>>", "assess-1", reason="test")

    def test_detokenize_enabled_with_reason(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from tprm.sanitize.vault import get_vault

        monkeypatch.setenv("TPRM_ALLOW_DETOKENIZE", "true")
        vault = get_vault()
        vault.store("<<EMAIL_ADDRESS_abc12345>>", "alice@example.com", "EMAIL_ADDRESS", "assess-1")
        result = vault.detokenize("<<EMAIL_ADDRESS_abc12345>>", "assess-1", reason="test access")
        assert result == "alice@example.com"

    def test_detokenize_requires_reason(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from tprm.sanitize.vault import get_vault
        from tprm.common.errors import VaultError

        monkeypatch.setenv("TPRM_ALLOW_DETOKENIZE", "true")
        vault = get_vault()
        vault.store("<<T>>", "val", "TYPE", "assess-1")
        with pytest.raises(VaultError, match="reason"):
            vault.detokenize("<<T>>", "assess-1", reason="")


class TestSanitizePipeline:
    def setup_method(self) -> None:
        from tprm.sanitize.vault import reset_vault
        reset_vault()

    def test_safe_blocks_pass_through(self) -> None:
        from tprm.sanitize.pipeline import sanitize_pipeline
        from tprm.common.models import Block, ClassifiedBlock, SensitivityLevel

        block = Block(doc_id="d1", page=0, text="Public information here")
        classified = ClassifiedBlock(
            block=block,
            block_level=SensitivityLevel.INTERNAL,
        )
        result = sanitize_pipeline([classified], "assess-1", "vendor-1")
        assert len(result) == 1
        assert result[0].text_sanitized == block.text
        assert result[0].applied == []

    def test_restricted_block_gets_redacted(self) -> None:
        from tprm.sanitize.pipeline import sanitize_pipeline
        from tprm.common.models import (
            Block, ClassifiedBlock, NLPContext, PIIEntity,
            PolicyDecision, SensitivityLevel,
        )

        block = Block(doc_id="d1", page=0, text="SSN: 123-45-6789 end")
        entity = PIIEntity(
            block_id=block.id, start=5, end=16,
            entity_type="US_SSN", text="123-45-6789", score=0.9, recognizer="ssn",
        )
        decision = PolicyDecision(
            entity_ref=f"{block.id}:5-16",
            entity_type="US_SSN",
            level=SensitivityLevel.RESTRICTED,
            action="redact",
            rule_id="R001",
            rationale="SSN always redacted",
        )
        ctx = NLPContext(
            block_id=block.id, doc_type="other", section_class="unknown",
            section_sensitivity_floor=SensitivityLevel.RESTRICTED,
        )
        classified = ClassifiedBlock(
            block=block, entities=[entity], ctx=ctx,
            decisions=[decision], block_level=SensitivityLevel.RESTRICTED,
        )

        result = sanitize_pipeline([classified], "assess-1", "vendor-1")
        assert len(result) == 1
        assert "123-45-6789" not in result[0].text_sanitized
        assert "[REDACTED:US_SSN]" in result[0].text_sanitized

    def test_idempotence(self) -> None:
        """Sanitizing already-sanitized text produces identical output."""
        from tprm.sanitize.pipeline import sanitize_pipeline
        from tprm.common.models import Block, ClassifiedBlock, SensitivityLevel

        # Text that is already fully sanitized
        block = Block(doc_id="d1", page=0, text="SSN: [REDACTED:US_SSN] here")
        classified = ClassifiedBlock(
            block=block,
            block_level=SensitivityLevel.INTERNAL,  # already sanitized → SAFE path
        )
        result = sanitize_pipeline([classified], "assess-2", "vendor-1")
        assert result[0].text_sanitized == block.text
