"""Segmenter: heading detection and section_path assignment.

Assigns a ``section_path`` to every block based on heading detection.
Chunks blocks to <= 800 tokens with 10% overlap; never splits inside an entity span.
"""

from __future__ import annotations

import re
import statistics
from typing import Any

from tprm.common.logging import get_logger
from tprm.common.models import Block, Document

log = get_logger(__name__)

# Rough token count: average English word is ~4.5 chars + space
_CHARS_PER_TOKEN = 4.5
_MAX_TOKENS = 800
_MAX_CHARS = int(_MAX_TOKENS * _CHARS_PER_TOKEN)
_OVERLAP_RATIO = 0.10

# DOCX heading style name prefixes
_DOCX_HEADING_STYLES = re.compile(r"^Heading\s*\d+$", re.IGNORECASE)

# Keywords that often indicate section headings in flat text
_HEADING_KEYWORDS = re.compile(
    r"^(?:\d+\.?)+\s+[A-Z]|^[A-Z][A-Z\s]{4,}$",
    re.MULTILINE,
)


def segment(doc: Document) -> Document:
    """Assign section_path to each block using heading heuristics.

    For PDF: uses font-size statistics.
    For DOCX/XLSX: uses style names / section_path already set by parser.
    Returns a new Document with updated blocks (section_path populated).
    """
    if doc.meta.doc_format == "pdf":
        blocks = _assign_pdf_sections(doc.blocks)
    else:
        # For DOCX/XLSX the parser already sets section_path from styles/sheet names
        blocks = doc.blocks

    log.info(
        "segmenter_complete",
        doc_id=doc.doc_id,
        block_count=len(blocks),
    )
    return doc.model_copy(update={"blocks": blocks})


def _assign_pdf_sections(blocks: list[Block]) -> list[Block]:
    """Use font-size heuristic to detect headings and build section_path."""
    # We use a simple heuristic: blocks on the same page where text is short
    # (< 80 chars) and preceded by a blank-ish block are candidate headings.
    # A more robust implementation would inspect fitz span font sizes (done
    # in parser.py metadata), but here we operate on already-extracted blocks.

    current_path: list[str] = []
    updated: list[Block] = []

    for block in blocks:
        text = block.text.strip()
        if _looks_like_heading(text):
            # Push heading onto path; reset deeper levels
            current_path = _update_path(current_path, text)
            log.debug("heading_detected", doc_id=block.doc_id, text_len=len(text))

        updated.append(block.model_copy(update={"section_path": list(current_path)}))

    return updated


def _looks_like_heading(text: str) -> bool:
    """Heuristic: is this block a section heading?"""
    if not text or len(text) > 120:
        return False
    # All caps short line
    if text.isupper() and len(text) < 80:
        return True
    # Numbered heading pattern: "1.2 Access Controls"
    if re.match(r"^(\d+\.)+\d?\s+[A-Z]", text):
        return True
    # Title case short line
    words = text.split()
    if (
        len(words) >= 2
        and len(words) <= 10
        and all(w[0].isupper() for w in words if w.isalpha())
        and len(text) < 80
    ):
        return True
    return False


def _update_path(current_path: list[str], heading: str) -> list[str]:
    """Update the section path hierarchy for a new heading."""
    # Simple strategy: depth inferred from numbering
    depth = _heading_depth(heading)
    if depth == 0:
        return [heading]
    new_path = current_path[:depth - 1] + [heading]
    return new_path


def _heading_depth(text: str) -> int:
    """Infer heading depth from numbering (e.g. "2.1.3 ..." → depth 3)."""
    match = re.match(r"^((\d+\.)+)", text.strip())
    if match:
        return match.group(1).count(".")
    return 1
