"""Unit tests for policy engine, sensitivity, and routing."""

from __future__ import annotations

import os

import pytest
from hypothesis import given, settings as hyp_settings
from hypothesis import strategies as st

os.environ.setdefault("TPRM_VAULT_KEY", "j5yCD74TW57pnqdPTzy_qHDrAjXX89hdQwdpM4Bf0l8=")
os.environ.setdefault("GATE_SIGNING_KEY", "test-gate-key")


def _make_entity(entity_type: str, score: float = 0.9) -> object:
    from tprm.common.models import PIIEntity
    return PIIEntity(
        block_id="b1", start=0, end=10,
        entity_type=entity_type, text="[test]", score=score, recognizer="test",
    )


def _make_ctx(section_class: str = "access_control", doc_type: str = "soc2_report") -> object:
    from tprm.common.models import NLPContext, SensitivityLevel
    from tprm.common.config import get_settings
    settings = get_settings()
    floor_map = settings.policy.get("section_floors", {})
    floor_str = floor_map.get(section_class, "INTERNAL")
    floor = SensitivityLevel.from_str(floor_str)
    return NLPContext(
        block_id="b1", doc_type=doc_type,
        section_class=section_class, section_sensitivity_floor=floor,
    )


def _make_block(source: str = "native") -> object:
    from tprm.common.models import Block
    return Block(doc_id="d1", page=0, text="Test block text", source=source)  # type: ignore[arg-type]


class TestPolicyEngine:
    def test_credentials_always_restricted(self) -> None:
        from tprm.policy.engine import PolicyEngine
        from tprm.common.models import SensitivityLevel

        engine = PolicyEngine()
        entity = _make_entity("CREDIT_CARD")
        ctx = _make_ctx()
        block = _make_block()
        decision = engine.decide(entity, ctx, block)  # type: ignore[arg-type]
        assert decision.level == SensitivityLevel.RESTRICTED
        assert decision.action == "redact"

    def test_api_key_always_restricted(self) -> None:
        from tprm.policy.engine import PolicyEngine
        from tprm.common.models import SensitivityLevel

        engine = PolicyEngine()
        decision = engine.decide(_make_entity("API_KEY"), _make_ctx(), _make_block())  # type: ignore[arg-type]
        assert decision.level == SensitivityLevel.RESTRICTED

    def test_public_org_name_internal(self) -> None:
        from tprm.policy.engine import PolicyEngine
        from tprm.common.models import SensitivityLevel

        engine = PolicyEngine()
        decision = engine.decide(_make_entity("ORG"), _make_ctx("audit_scope"), _make_block())  # type: ignore[arg-type]
        assert decision.level >= SensitivityLevel.INTERNAL

    def test_example_marker_lowers_level(self) -> None:
        from tprm.policy.engine import PolicyEngine
        from tprm.common.models import NLPContext, SensitivityLevel

        engine = PolicyEngine()
        entity = _make_entity("EMAIL_ADDRESS")
        from tprm.common.config import get_settings
        settings = get_settings()
        # Use audit_scope which has floor=INTERNAL (lower than access_control=CONFIDENTIAL)
        floor_str = settings.policy.get("section_floors", {}).get("audit_scope", "INTERNAL")
        ctx = NLPContext(
            block_id="b1", doc_type="soc2_report", section_class="audit_scope",
            is_example=True,
            section_sensitivity_floor=SensitivityLevel.from_str(floor_str),
        )
        block = _make_block()
        decision = engine.decide(entity, ctx, block)  # type: ignore[arg-type]
        # Rule R003 fires (PUBLIC) but floor is INTERNAL → result is <= INTERNAL
        assert decision.level <= SensitivityLevel.INTERNAL

    def test_explain_returns_rule_id(self) -> None:
        from tprm.policy.engine import PolicyEngine

        engine = PolicyEngine()
        decision = engine.decide(_make_entity("CREDIT_CARD"), _make_ctx(), _make_block())  # type: ignore[arg-type]
        explanation = engine.explain(decision)
        assert "R001" in explanation or "RESTRICTED" in explanation

    def test_ocr_low_conf_escalates(self) -> None:
        from tprm.policy.engine import PolicyEngine
        from tprm.common.models import SensitivityLevel

        engine = PolicyEngine()
        entity = _make_entity("EMAIL_ADDRESS")
        ctx = _make_ctx()
        block = _make_block(source="ocr")
        block_with_low_conf = block.model_copy(update={"ocr_conf": 30.0})  # type: ignore[union-attr]
        decision = engine.decide(entity, ctx, block_with_low_conf)  # type: ignore[arg-type]
        # With ocr_conf < 40, rule R010 should escalate
        assert decision.level >= SensitivityLevel.CONFIDENTIAL

    def test_dpa_personal_data_restricted(self) -> None:
        from tprm.policy.engine import PolicyEngine
        from tprm.common.models import SensitivityLevel

        engine = PolicyEngine()
        decision = engine.decide(
            _make_entity("EMAIL_ADDRESS"),
            _make_ctx(doc_type="dpa"),
            _make_block(),
        )  # type: ignore[arg-type]
        assert decision.level == SensitivityLevel.RESTRICTED


class TestSensitivityMonotonicity:
    """Property tests: sensitivity is monotonic."""

    @given(
        base_levels=st.lists(
            st.sampled_from([0, 1, 2, 3]),
            min_size=1, max_size=5,
        ),
        additional_level=st.sampled_from([0, 1, 2, 3]),
    )
    @hyp_settings(max_examples=50)
    def test_adding_entity_never_lowers_level(
        self, base_levels: list[int], additional_level: int
    ) -> None:
        """Adding a sensitive entity to a block never lowers the block level."""
        from tprm.common.models import Block, ClassifiedBlock, NLPContext, PolicyDecision, SensitivityLevel
        from tprm.sensitivity.levels import score_block

        block = Block(doc_id="d1", page=0, text="test")
        ctx = NLPContext(
            block_id=block.id, doc_type="other", section_class="unknown",
            section_sensitivity_floor=SensitivityLevel.INTERNAL,
        )

        def make_decisions(levels: list[int]) -> list[PolicyDecision]:
            return [
                PolicyDecision(
                    entity_ref=f"b1:0-{i}",
                    entity_type="EMAIL_ADDRESS",
                    level=SensitivityLevel(lvl),
                    action="keep",
                    rule_id="R099",
                    rationale="test",
                )
                for i, lvl in enumerate(levels)
            ]

        # Base classification
        base_decisions = make_decisions(base_levels)
        cb_base = ClassifiedBlock(block=block, ctx=ctx, decisions=base_decisions)
        cb_base = score_block(cb_base)

        # Add the extra entity
        all_decisions = make_decisions(base_levels + [additional_level])
        cb_extended = ClassifiedBlock(block=block, ctx=ctx, decisions=all_decisions)
        cb_extended = score_block(cb_extended)

        # Level must not go down
        assert cb_extended.block_level >= cb_base.block_level


class TestRouting:
    def test_internal_routes_safe(self) -> None:
        from tprm.common.models import Block, ClassifiedBlock, SensitivityLevel
        from tprm.sensitivity.scorer import route

        block = Block(doc_id="d1", page=0, text="internal info")
        cb = ClassifiedBlock(block=block, block_level=SensitivityLevel.INTERNAL)
        assert route(cb) == "SAFE"

    def test_public_routes_safe(self) -> None:
        from tprm.common.models import Block, ClassifiedBlock, SensitivityLevel
        from tprm.sensitivity.scorer import route

        block = Block(doc_id="d1", page=0, text="public cert")
        cb = ClassifiedBlock(block=block, block_level=SensitivityLevel.PUBLIC)
        assert route(cb) == "SAFE"

    def test_confidential_routes_sensitive(self) -> None:
        from tprm.common.models import Block, ClassifiedBlock, SensitivityLevel
        from tprm.sensitivity.scorer import route

        block = Block(doc_id="d1", page=0, text="confidential data")
        cb = ClassifiedBlock(block=block, block_level=SensitivityLevel.CONFIDENTIAL)
        assert route(cb) == "SENSITIVE"

    def test_restricted_routes_sensitive(self) -> None:
        from tprm.common.models import Block, ClassifiedBlock, SensitivityLevel
        from tprm.sensitivity.scorer import route

        block = Block(doc_id="d1", page=0, text="restricted SSN")
        cb = ClassifiedBlock(block=block, block_level=SensitivityLevel.RESTRICTED)
        assert route(cb) == "SENSITIVE"
