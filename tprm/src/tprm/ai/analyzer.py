"""AI Risk Analysis — public interface: analyze(payload) -> AIRiskResult.

Only accepts GateApprovedPayload (HMAC-verified at entry).
Uses LangChain -> Ollama (local) -> PydanticOutputParser.
FakeLLM available for deterministic testing.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any, Protocol, runtime_checkable

from tprm.ai.prompts import build_prompt
from tprm.common.errors import LLMError, LLMParseError, SignatureError
from tprm.common.logging import get_logger
from tprm.common.models import AIRiskResult, GateApprovedPayload, RawRisk, SanitizedBlock
from tprm.gate.verifier import verify_gate_approved

log = get_logger(__name__)

_MAX_RETRIES = 2
_MAX_TOKENS_PER_SECTION = 3000


@runtime_checkable
class LLMBackend(Protocol):
    """Protocol for LLM backends (ChatOllama or FakeLLM)."""

    def invoke(self, messages: list[dict[str, str]]) -> Any: ...


class FakeLLM:
    """Deterministic test LLM — returns fixed risk items keyed by section_class."""

    FAKE_RESPONSES: dict[str, list[dict[str, Any]]] = {
        "access_control": [
            {
                "id": "risk-fake-001",
                "title": "Missing MFA Enforcement",
                "description": "The vendor has not implemented mandatory MFA for all privileged accounts.",
                "evidence_block_ids": [],
                "claimed_category": "ACCESS_MGMT",
                "confidence": 0.85,
            }
        ],
        "encryption": [
            {
                "id": "risk-fake-002",
                "title": "Weak TLS Configuration",
                "description": "Legacy TLS 1.0/1.1 protocols may still be supported.",
                "evidence_block_ids": [],
                "claimed_category": "ENCRYPTION",
                "confidence": 0.75,
            }
        ],
        "default": [
            {
                "id": "risk-fake-003",
                "title": "Generic Security Risk",
                "description": "A security control gap was identified in the reviewed section.",
                "evidence_block_ids": [],
                "claimed_category": "INFO_SEC",
                "confidence": 0.60,
            }
        ],
    }

    def invoke(self, messages: list[dict[str, str]]) -> Any:
        """Return a deterministic JSON response based on section_class in messages."""
        # Extract section_class from the user message
        user_content = next((m.get("content", "") for m in messages if m.get("role") == "user"), "")
        section_class = "default"
        match = re.search(r"Section class: (\w+)", user_content)
        if match:
            section_class = match.group(1)

        items = self.FAKE_RESPONSES.get(section_class, self.FAKE_RESPONSES["default"])

        # Extract block IDs from prompt to populate evidence
        block_id_match = re.search(r"Available block IDs for evidence citation: ([^\n]+)", user_content)
        block_ids = []
        if block_id_match:
            block_ids = [b.strip() for b in block_id_match.group(1).split(",")][:1]

        populated_items = []
        for item in items:
            populated_item = dict(item)
            populated_item["evidence_block_ids"] = block_ids if block_ids else ["fake-block-001"]
            populated_items.append(populated_item)

        result = {"items": populated_items}

        class FakeMessage:
            content = json.dumps(result)

        return FakeMessage()


def _build_langchain_llm(settings: Any) -> Any:
    """Build a ChatOllama LangChain LLM instance."""
    try:
        from langchain_ollama import ChatOllama  # type: ignore[import-untyped]
        return ChatOllama(
            model=settings.llm_model,
            base_url=settings.ollama_url,
            temperature=0,
        )
    except ImportError as exc:
        raise LLMError("langchain-ollama is not installed") from exc


async def analyze(
    payload: GateApprovedPayload,
    llm: LLMBackend | None = None,
) -> AIRiskResult:
    """Analyze a gate-approved payload for security risks.

    Args:
        payload: Must be a valid, HMAC-signed GateApprovedPayload.
        llm: Optional LLM backend override (use FakeLLM for tests).

    Returns:
        AIRiskResult with deduplicated risk items.

    Raises:
        SignatureError: If the payload signature is invalid.
        LLMError: If all LLM retries fail.
    """
    # ── Entry guard: verify signature ─────────────────────────────────────────
    verify_gate_approved(payload)

    from tprm.common.config import get_settings
    settings = get_settings()

    if llm is None:
        llm = _build_langchain_llm(settings)

    # ── Group blocks by section_class for batched analysis ───────────────────
    sections: dict[str, list[SanitizedBlock]] = defaultdict(list)
    for block in payload.blocks:
        sections[block.section_class].append(block)

    all_items: list[RawRisk] = []
    valid_block_ids = {b.block_id for b in payload.blocks}

    for section_class, section_blocks in sections.items():
        combined_text = "\n\n".join(
            f"[Block {b.block_id}]\n{b.text_sanitized}"
            for b in section_blocks
        )
        block_ids = [b.block_id for b in section_blocks]

        # Chunk if too long (map-reduce)
        chunks = _chunk_text(combined_text, block_ids, _MAX_TOKENS_PER_SECTION)

        for chunk_text, chunk_block_ids in chunks:
            system_prompt, user_prompt = build_prompt(
                section_class=section_class,
                doc_type=payload.doc_type,
                sanitized_text=chunk_text,
                block_ids=chunk_block_ids,
            )
            items = await _invoke_with_retry(
                llm=llm,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                valid_block_ids=valid_block_ids,
                max_retries=settings.llm_max_retries,
            )
            all_items.extend(items)

    # ── Deduplicate ────────────────────────────────────────────────────────────
    deduplicated = _deduplicate_items(all_items)

    log.info(
        "ai_analysis_complete",
        doc_id=payload.doc_id,
        raw_items=len(all_items),
        deduped_items=len(deduplicated),
    )
    return AIRiskResult(items=deduplicated)


async def _invoke_with_retry(
    llm: LLMBackend,
    system_prompt: str,
    user_prompt: str,
    valid_block_ids: set[str],
    max_retries: int = 2,
) -> list[RawRisk]:
    """Invoke LLM with JSON-repair retry. Drops items without valid evidence IDs."""
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            response = llm.invoke(messages)
            content = response.content if hasattr(response, "content") else str(response)

            # Parse JSON
            parsed = _parse_json_response(content)
            result = AIRiskResult.model_validate(parsed)

            # Drop items without valid evidence block IDs
            valid_items = [
                item for item in result.items
                if any(bid in valid_block_ids for bid in item.evidence_block_ids)
            ]

            log.info(
                "llm_response_parsed",
                attempt=attempt,
                raw_items=len(result.items),
                valid_items=len(valid_items),
            )
            return valid_items

        except Exception as exc:
            last_error = exc
            log.warning("llm_retry", attempt=attempt, error=str(exc))
            if attempt < max_retries:
                # Add repair instruction
                messages.append({"role": "assistant", "content": content if "content" in dir() else ""})
                messages.append({
                    "role": "user",
                    "content": "The previous response was not valid JSON. Please output ONLY valid JSON matching the schema.",
                })

    raise LLMParseError(f"LLM failed after {max_retries + 1} attempts: {last_error}") from last_error


def _parse_json_response(content: str) -> dict[str, Any]:
    """Parse JSON from LLM response, with basic repair for common issues."""
    content = content.strip()

    # Strip markdown code fences
    content = re.sub(r"^```(?:json)?\s*", "", content, flags=re.MULTILINE)
    content = re.sub(r"\s*```$", "", content, flags=re.MULTILINE)

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Try json_repair if available
        try:
            from json_repair import repair_json  # type: ignore[import-untyped]
            repaired = repair_json(content)
            return json.loads(repaired)
        except Exception:
            pass
        raise


def _chunk_text(
    text: str,
    block_ids: list[str],
    max_chars: int,
) -> list[tuple[str, list[str]]]:
    """Split text into chunks of max_chars, preserving block boundaries."""
    if len(text) <= max_chars:
        return [(text, block_ids)]

    # Split by block markers
    parts = re.split(r"(\[Block [^\]]+\])", text)
    chunks: list[tuple[str, list[str]]] = []
    current_text = ""
    current_ids: list[str] = []

    for part in parts:
        block_match = re.match(r"\[Block ([^\]]+)\]", part)
        if block_match:
            bid = block_match.group(1)
            if bid in block_ids:
                current_ids.append(bid)

        if len(current_text) + len(part) > max_chars and current_text:
            chunks.append((current_text, list(current_ids)))
            current_text = part
            current_ids = [bid for bid in current_ids[-1:]]
        else:
            current_text += part

    if current_text:
        chunks.append((current_text, current_ids))

    return chunks or [(text[:max_chars], block_ids)]


def _deduplicate_items(items: list[RawRisk]) -> list[RawRisk]:
    """Remove duplicate risk items by title similarity."""
    seen_titles: set[str] = set()
    unique: list[RawRisk] = []

    for item in items:
        # Simple title-based dedup (embedding-based in risk extractor)
        title_key = item.title.lower().strip()
        if title_key not in seen_titles:
            seen_titles.add(title_key)
            unique.append(item)

    return unique
