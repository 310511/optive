"""Policy Engine — deterministic, rule-based PII sensitivity decisions.

Public interface: PolicyEngine.decide() and PolicyEngine.explain().
"""

from __future__ import annotations

from typing import Any

from tprm.common.config import get_settings
from tprm.common.errors import PolicyConfigError, PolicyDecisionError
from tprm.common.logging import get_logger
from tprm.common.models import Block, NLPContext, PIIEntity, PolicyDecision, SensitivityLevel
from tprm.policy.rules import PolicyRule, load_rules, matches

log = get_logger(__name__)


def _default_action(level: SensitivityLevel) -> str:
    """Return the default action for a sensitivity level."""
    match level:
        case SensitivityLevel.PUBLIC:
            return "keep"
        case SensitivityLevel.INTERNAL:
            return "keep"
        case SensitivityLevel.CONFIDENTIAL:
            return "tokenize"
        case SensitivityLevel.RESTRICTED:
            return "redact"
        case _:
            return "redact"


class PolicyEngine:
    """Deterministic policy engine loaded from config/policy.yaml.

    Thread-safe: instances are immutable after construction.
    """

    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        if policy is None:
            policy = get_settings().policy
        self._policy = policy
        try:
            self._rules: list[PolicyRule] = load_rules(policy)
        except Exception as exc:
            raise PolicyConfigError(f"Failed to load policy rules: {exc}") from exc

        self._impact_table: dict[str, dict[str, str]] = policy.get("impact_table", {})

    def decide(
        self,
        entity: PIIEntity,
        ctx: NLPContext,
        block: Block,
    ) -> PolicyDecision:
        """Apply the policy rule set and return a PolicyDecision.

        First-match semantics: rules are evaluated in priority order.
        Falls back to impact_table, then catch-all CONFIDENTIAL.
        Level is guaranteed to be >= ctx.section_sensitivity_floor (monotonicity).
        """
        entity_ref = f"{entity.block_id}:{entity.start}-{entity.end}"

        # ── Phase 1: evaluate ordered rules ──────────────────────────────────
        for rule in self._rules:
            if not matches(rule, entity, ctx, block):
                continue

            # level_boost rules (e.g., OCR low confidence → +1 level)
            if rule.level_boost is not None:
                base_level = self._impact_table_level(entity.entity_type)
                boosted = SensitivityLevel(
                    min(int(base_level) + rule.level_boost, int(SensitivityLevel.RESTRICTED))
                )
                final_level = max(boosted, ctx.section_sensitivity_floor)
                action = _default_action(final_level)
                return PolicyDecision(
                    entity_ref=entity_ref,
                    entity_type=entity.entity_type,
                    level=final_level,
                    action=action,
                    rule_id=rule.id,
                    rationale=rule.rationale,
                )

            if rule.sensitivity_level is not None:
                level = rule.sensitivity_level
                action = rule.action

                # Enforce monotonicity: level cannot go below section floor
                level = max(level, ctx.section_sensitivity_floor)

                # If level changed due to floor, update action accordingly
                if level != rule.sensitivity_level:
                    action = _default_action(level)

                return PolicyDecision(
                    entity_ref=entity_ref,
                    entity_type=entity.entity_type,
                    level=level,
                    action=action,
                    rule_id=rule.id,
                    rationale=rule.rationale,
                )

        # ── Phase 2: fall back to impact table ───────────────────────────────
        impact_level = self._impact_table_level(entity.entity_type)
        impact_action = self._impact_table_action(entity.entity_type)
        final_level = max(impact_level, ctx.section_sensitivity_floor)
        final_action = impact_action if final_level == impact_level else _default_action(final_level)

        log.debug(
            "policy_impact_table_fallback",
            entity_type=entity.entity_type,
            level=final_level.name,
        )
        return PolicyDecision(
            entity_ref=entity_ref,
            entity_type=entity.entity_type,
            level=final_level,
            action=final_action,
            rule_id="IMPACT_TABLE_FALLBACK",
            rationale=f"Impact table default for {entity.entity_type}",
        )

    def explain(self, decision: PolicyDecision) -> str:
        """Return a human-readable explanation of why a decision was made."""
        rule_id = decision.rule_id
        matching_rule = next((r for r in self._rules if r.id == rule_id), None)

        if matching_rule:
            return (
                f"Rule {rule_id} (priority {matching_rule.priority}) matched.\n"
                f"Conditions: {matching_rule.when}\n"
                f"Decision: level={decision.level.name}, action={decision.action}\n"
                f"Rationale: {matching_rule.rationale}"
            )
        return (
            f"Rule ID: {rule_id}\n"
            f"Decision: level={decision.level.name}, action={decision.action}\n"
            f"Rationale: {decision.rationale}"
        )

    def _impact_table_level(self, entity_type: str) -> SensitivityLevel:
        entry = self._impact_table.get(entity_type, {})
        level_str = entry.get("level", "CONFIDENTIAL")
        try:
            return SensitivityLevel.from_str(level_str)
        except (KeyError, ValueError):
            return SensitivityLevel.CONFIDENTIAL

    def _impact_table_action(self, entity_type: str) -> str:
        entry = self._impact_table.get(entity_type, {})
        return entry.get("action", "tokenize")
