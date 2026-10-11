"""Policy rule model and condition matcher.

Rules are loaded from config/policy.yaml.
Each rule has a ``when`` dict with optional conditions.
First-match semantics (rules sorted by priority ascending).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from tprm.common.models import Block, NLPContext, PIIEntity, SensitivityLevel


class PolicyRule(BaseModel):
    """A single policy rule loaded from YAML."""

    id: str
    priority: int
    when: dict[str, Any]
    level: str | None = None
    level_boost: int | None = None  # boost level by N steps (for OCR escalation)
    action: str = "keep"
    rationale: str = ""

    @property
    def sensitivity_level(self) -> SensitivityLevel | None:
        if self.level:
            return SensitivityLevel.from_str(self.level)
        return None


def load_rules(policy: dict[str, Any]) -> list[PolicyRule]:
    """Load and sort rules from the policy config dict."""
    raw_rules = policy.get("rules", [])
    rules = [PolicyRule(**r) for r in raw_rules]
    return sorted(rules, key=lambda r: r.priority)


def matches(
    rule: PolicyRule,
    entity: PIIEntity,
    ctx: NLPContext,
    block: Block,
) -> bool:
    """Return True if all conditions in ``rule.when`` are satisfied."""
    when = rule.when

    if not when:
        return True  # catch-all rule

    # entity_type: list[str] or str
    if "entity_type" in when:
        allowed = when["entity_type"]
        if isinstance(allowed, str):
            allowed = [allowed]
        if entity.entity_type not in allowed:
            return False

    # section_class: list[str] or str
    if "section_class" in when:
        allowed = when["section_class"]
        if isinstance(allowed, str):
            allowed = [allowed]
        if ctx.section_class not in allowed:
            return False

    # doc_type: list[str] or str
    if "doc_type" in when:
        allowed = when["doc_type"]
        if isinstance(allowed, str):
            allowed = [allowed]
        if ctx.doc_type not in allowed:
            return False

    # source: list[str] or str
    if "source" in when:
        allowed = when["source"]
        if isinstance(allowed, str):
            allowed = [allowed]
        if block.source not in allowed:
            return False

    # score_lt / score_gt
    if "score_lt" in when and entity.score >= when["score_lt"]:
        return False
    if "score_gt" in when and entity.score <= when["score_gt"]:
        return False

    # ocr_conf_lt: block OCR confidence below threshold
    if "ocr_conf_lt" in when:
        conf = block.ocr_conf if block.ocr_conf is not None else 100.0
        if conf >= when["ocr_conf_lt"]:
            return False

    # is_example
    if "is_example" in when:
        expected = bool(when["is_example"])
        if ctx.is_example != expected:
            return False

    # is_negated
    if "is_negated" in when:
        expected = bool(when["is_negated"])
        if ctx.is_negated != expected:
            return False

    # has_relation: check if any relation of given type exists for this entity's block
    if "has_relation" in when:
        wanted_relations = when["has_relation"]
        if isinstance(wanted_relations, str):
            wanted_relations = [wanted_relations]
        entity_relations = [r for r in ctx.relations if entity.block_id in r.block_ids]
        found_types = {r.relation_type for r in entity_relations}
        # Also check target_entity_id for context markers like "context:signature_block"
        context_markers = {r.target_entity_id.split(":")[-1] for r in entity_relations}
        if not any(w in found_types or w in context_markers for w in wanted_relations):
            return False

    return True
