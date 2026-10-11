"""OCR helpers using Tesseract via pytesseract.

Only called for pages / images where native text is sparse.
Low-confidence words (< threshold) are flagged but retained in the block text;
the block's ``ocr_conf`` reflects the mean word confidence.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING, Any

from tprm.common.logging import get_logger

if TYPE_CHECKING:
    import fitz  # PyMuPDF

log = get_logger(__name__)

_OCR_CONF_DROP_THRESHOLD = 40  # words below this confidence are flagged


def ocr_pixmap(pixmap: Any, doc_id: str, page_num: int, conf_threshold: int = _OCR_CONF_DROP_THRESHOLD) -> tuple[str, float]:
    """Run Tesseract OCR on a PyMuPDF pixmap.

    Returns:
        (text, mean_confidence) where text has low-confidence words marked
        with [LOW_CONF] suffix for downstream flagging.
    """
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        log.warning("ocr_unavailable", doc_id=doc_id, page=page_num)
        return "", 0.0

    # Convert pixmap to PIL image
    img_bytes = pixmap.tobytes("png")
    image = Image.open(io.BytesIO(img_bytes))

    try:
        data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    except Exception as exc:
        log.warning("ocr_failed", doc_id=doc_id, page=page_num, error=str(exc))
        return "", 0.0

    words: list[str] = []
    confidences: list[float] = []

    for i, text in enumerate(data["text"]):
        word = str(text).strip()
        if not word:
            continue
        try:
            conf = float(data["conf"][i])
        except (ValueError, TypeError):
            conf = 0.0

        if conf < 0:
            # Tesseract uses -1 for non-word elements (e.g. block separators)
            continue

        confidences.append(conf)
        if conf < conf_threshold:
            words.append(f"{word}[LOW_CONF]")
        else:
            words.append(word)

    text_out = " ".join(words)
    mean_conf = sum(confidences) / len(confidences) if confidences else 0.0
    return text_out, mean_conf


def ocr_image_bytes(image_bytes: bytes, doc_id: str, block_hint: str = "", conf_threshold: int = _OCR_CONF_DROP_THRESHOLD) -> tuple[str, float]:
    """Run OCR on raw image bytes (e.g. embedded DOCX images).

    Returns (text, mean_confidence).
    """
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        log.warning("ocr_unavailable_for_image", doc_id=doc_id)
        return "", 0.0

    try:
        image = Image.open(io.BytesIO(image_bytes))
        data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    except Exception as exc:
        log.warning("ocr_image_failed", doc_id=doc_id, hint=block_hint, error=str(exc))
        return "", 0.0

    words: list[str] = []
    confidences: list[float] = []

    for i, text in enumerate(data["text"]):
        word = str(text).strip()
        if not word:
            continue
        try:
            conf = float(data["conf"][i])
        except (ValueError, TypeError):
            conf = 0.0
        if conf < 0:
            continue
        confidences.append(conf)
        if conf < conf_threshold:
            words.append(f"{word}[LOW_CONF]")
        else:
            words.append(word)

    text_out = " ".join(words)
    mean_conf = sum(confidences) / len(confidences) if confidences else 0.0
    return text_out, mean_conf
