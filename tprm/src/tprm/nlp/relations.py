"""Entity relationship graph builder.

Builds relationships between entities within and across blocks:
- person ↔ role (nsubj/nmod dependency arcs)
- person ↔ email (co-occurrence within a block)
- org ↔ contract
- system ↔ IP / hostname

Also assigns canonical IDs so the same entity text maps to the same ID
across all blocks in a document.
"""

from __future__ import annotations

import re
from collections import defaultdict

from tprm.common.logging import get_logger
from tprm.common.models import Block, PIIEntity, Relation

log = get_logger(__name__)

# Role noun heuristics (for when spaCy isn't available)
_ROLE_NOUNS = re.compile(
    r"\b(?:CEO|CTO|CISO|CFO|manager|director|officer|engineer|analyst|"
    r"administrator|admin|owner|contact|representative|rep|lead|head|"
    r"signatory|auditor|reviewer|approver)\b",
    re.IGNORECASE,
)


def build_relations(
    blocks: list[Block],
    entities: list[PIIEntity],
) -> list[Relation]:
    """Build entity relationships across all blocks.

    Args:
        blocks: All blocks in the document.
        entities: All detected PII entities.

    Returns:
        List of Relation objects linking entities.
    """
    # Group entities by block_id for efficient lookup
    entities_by_block: dict[str, list[PIIEntity]] = defaultdict(list)
    for e in entities:
        entities_by_block[e.block_id].append(e)

    # Assign canonical IDs: same normalised entity text → same canonical_id
    canonical_map: dict[str, str] = {}
    entity_canonical: dict[str, str] = {}  # entity (block_id:start-end) → canonical_id

    for entity in entities:
        key = f"{entity.entity_type}:{entity.text.strip().lower()}"
        if key not in canonical_map:
            canonical_map[key] = f"canon_{len(canonical_map):04d}"
        entity_canonical[f"{entity.block_id}:{entity.start}-{entity.end}"] = canonical_map[key]

    relations: list[Relation] = []

    for block in blocks:
        block_entities = entities_by_block.get(block.id, [])
        if not block_entities:
            continue

        text = block.text

        # Try spaCy for dependency-based relations
        nlp_relations = _extract_spacy_relations(text, block.id, block_entities)
        relations.extend(nlp_relations)

        # Co-occurrence heuristic: PERSON + EMAIL in same block → person_email relation
        persons = [e for e in block_entities if e.entity_type == "PERSON"]
        emails = [e for e in block_entities if e.entity_type == "EMAIL_ADDRESS"]
        phones = [e for e in block_entities if e.entity_type == "PHONE_NUMBER"]
        orgs = [e for e in block_entities if e.entity_type == "ORG"]
        ips = [e for e in block_entities if e.entity_type in ("IP_ADDRESS", "INTERNAL_HOSTNAME")]
        contracts = [e for e in block_entities if e.entity_type == "CONTRACT_NUMBER"]

        for person in persons:
            p_ref = f"{person.block_id}:{person.start}-{person.end}"
            for email in emails:
                e_ref = f"{email.block_id}:{email.start}-{email.end}"
                relations.append(Relation(
                    source_entity_id=p_ref,
                    target_entity_id=e_ref,
                    relation_type="person_email",
                    block_ids=[block.id],
                ))
            for phone in phones:
                ph_ref = f"{phone.block_id}:{phone.start}-{phone.end}"
                relations.append(Relation(
                    source_entity_id=p_ref,
                    target_entity_id=ph_ref,
                    relation_type="person_phone",
                    block_ids=[block.id],
                ))
            # Detect role from context
            role_match = _ROLE_NOUNS.search(text)
            if role_match:
                relations.append(Relation(
                    source_entity_id=p_ref,
                    target_entity_id=f"role:{role_match.group(0).lower()}",
                    relation_type="person_role",
                    block_ids=[block.id],
                ))
            # Detect signature block context
            if re.search(r"\b(?:signed|signature|signatory|authorized by)\b", text, re.IGNORECASE):
                relations.append(Relation(
                    source_entity_id=p_ref,
                    target_entity_id="context:signature_block",
                    relation_type="signature_block",
                    block_ids=[block.id],
                ))
            # Detect auditor context
            if re.search(r"\b(?:auditor|audit firm|audited by)\b", text, re.IGNORECASE):
                relations.append(Relation(
                    source_entity_id=p_ref,
                    target_entity_id="context:auditor_role",
                    relation_type="auditor_role",
                    block_ids=[block.id],
                ))

        for org in orgs:
            o_ref = f"{org.block_id}:{org.start}-{org.end}"
            for contract in contracts:
                c_ref = f"{contract.block_id}:{contract.start}-{contract.end}"
                relations.append(Relation(
                    source_entity_id=o_ref,
                    target_entity_id=c_ref,
                    relation_type="org_contract",
                    block_ids=[block.id],
                ))

    log.debug("relations_built", relation_count=len(relations))
    return relations


def _extract_spacy_relations(
    text: str,
    block_id: str,
    entities: list[PIIEntity],
) -> list[Relation]:
    """Use spaCy dependency parse for relation extraction if available."""
    try:
        import spacy  # type: ignore[import-untyped]

        nlp = _get_spacy_nlp()
        if nlp is None:
            return []

        doc = nlp(text[:1000])  # limit to 1000 chars for performance
        relations: list[Relation] = []

        for token in doc:
            # person ↔ role via nsubj/nmod arc
            if token.dep_ in ("nsubj", "nmod") and token.ent_type_ == "PERSON":
                head_text = token.head.text.lower()
                if _ROLE_NOUNS.search(head_text):
                    person_ref = _find_entity_ref(block_id, entities, token.idx)
                    if person_ref:
                        relations.append(Relation(
                            source_entity_id=person_ref,
                            target_entity_id=f"role:{head_text}",
                            relation_type="person_role",
                            block_ids=[block_id],
                        ))

        return relations
    except Exception:
        return []


_SPACY_NLP: object | None = None
_SPACY_LOADED = False


def _get_spacy_nlp() -> object | None:
    """Load spaCy NLP model (cached)."""
    global _SPACY_NLP, _SPACY_LOADED  # noqa: PLW0603
    if _SPACY_LOADED:
        return _SPACY_NLP
    _SPACY_LOADED = True
    try:
        import spacy  # type: ignore[import-untyped]

        try:
            _SPACY_NLP = spacy.load("en_core_web_lg")
        except OSError:
            try:
                _SPACY_NLP = spacy.load("en_core_web_sm")
            except OSError:
                log.warning("spacy_model_not_found")
                _SPACY_NLP = None
    except ImportError:
        _SPACY_NLP = None
    return _SPACY_NLP


def _find_entity_ref(block_id: str, entities: list[PIIEntity], char_idx: int) -> str | None:
    """Find entity ref string for an entity at/near char_idx."""
    for entity in entities:
        if entity.start <= char_idx < entity.end:
            return f"{block_id}:{entity.start}-{entity.end}"
    return None


def get_canonical_ids(entities: list[PIIEntity]) -> dict[str, str]:
    """Return a mapping from entity ref to canonical_id.

    Same entity_type + normalised text → same canonical_id.
    """
    canonical_map: dict[str, str] = {}
    result: dict[str, str] = {}

    for entity in entities:
        key = f"{entity.entity_type}:{entity.text.strip().lower()}"
        if key not in canonical_map:
            canonical_map[key] = f"canon_{len(canonical_map):04d}"
        ref = f"{entity.block_id}:{entity.start}-{entity.end}"
        result[ref] = canonical_map[key]

    return result
