"""Unit tests for ingestion/parser.py."""

from __future__ import annotations

import io
import os
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest

from tprm.common.errors import FileTooLarge, UnsupportedFormat, ZipBombDetected
from tprm.common.models import Document


def _set_env() -> None:
    os.environ.setdefault("TPRM_VAULT_KEY", "j5yCD74TW57pnqdPTzy_qHDrAjXX89hdQwdpM4Bf0l8=")
    os.environ.setdefault("GATE_SIGNING_KEY", "test-gate-key")


class TestMagicByteDetection:
    def setup_method(self) -> None:
        _set_env()

    def test_unsupported_format_raises(self, tmp_path: Path) -> None:
        from tprm.ingestion.parser import parse

        bad_file = tmp_path / "test.txt"
        bad_file.write_bytes(b"Hello World plain text file content here")
        with pytest.raises(UnsupportedFormat):
            parse(bad_file)

    def test_png_raises_unsupported(self, tmp_path: Path) -> None:
        from tprm.ingestion.parser import parse

        # PNG magic bytes
        png_file = tmp_path / "test.png"
        png_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        with pytest.raises(UnsupportedFormat):
            parse(png_file)

    def test_file_too_large_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from tprm.ingestion import parser

        large_file = tmp_path / "big.pdf"
        large_file.write_bytes(b"%PDF" + b"x" * 100)

        monkeypatch.setattr(
            parser,
            "get_settings",
            lambda: type("S", (), {"policy": {"limits": {"max_file_size_bytes": 10}}})(),
        )
        with pytest.raises(FileTooLarge):
            parser.parse(large_file)


class TestPDFParsing:
    def setup_method(self) -> None:
        _set_env()

    def test_parse_synthetic_pdf(self) -> None:
        from tests.fixtures.make_pdf import CANARIES, make_synthetic_pdf
        from tprm.ingestion.parser import parse

        with tempfile.TemporaryDirectory() as tmp:
            path = make_synthetic_pdf(Path(tmp))
            doc = parse(path, vendor_id="vendor-test")

        assert isinstance(doc, Document)
        assert doc.vendor_id == "vendor-test"
        assert len(doc.blocks) > 0
        assert doc.meta.doc_format == "pdf"
        assert len(doc.sha256) == 64

        all_text = " ".join(b.text for b in doc.blocks)
        # Canaries should be in the extracted text (before PII detection)
        assert CANARIES["EMAIL"] in all_text or any(
            CANARIES["EMAIL"] in b.text for b in doc.blocks
        )

    def test_pdf_blocks_have_page_number(self) -> None:
        from tests.fixtures.make_pdf import make_synthetic_pdf
        from tprm.ingestion.parser import parse

        with tempfile.TemporaryDirectory() as tmp:
            path = make_synthetic_pdf(Path(tmp))
            doc = parse(path, vendor_id="v1")

        pages = {b.page for b in doc.blocks}
        assert len(pages) >= 1

    def test_pdf_native_blocks_have_source_native(self) -> None:
        from tests.fixtures.make_pdf import make_synthetic_pdf
        from tprm.ingestion.parser import parse

        with tempfile.TemporaryDirectory() as tmp:
            path = make_synthetic_pdf(Path(tmp))
            doc = parse(path, vendor_id="v1")

        native_blocks = [b for b in doc.blocks if b.source == "native"]
        assert len(native_blocks) > 0


class TestDOCXParsing:
    def setup_method(self) -> None:
        _set_env()

    def test_parse_synthetic_docx(self) -> None:
        from tests.fixtures.make_docx import make_synthetic_docx
        from tprm.ingestion.parser import parse

        with tempfile.TemporaryDirectory() as tmp:
            path = make_synthetic_docx(Path(tmp))
            doc = parse(path, vendor_id="vendor-test")

        assert isinstance(doc, Document)
        assert doc.meta.doc_format == "docx"
        assert len(doc.blocks) > 0

    def test_docx_table_cells_are_table_cell_blocks(self) -> None:
        from tests.fixtures.make_docx import make_synthetic_docx
        from tprm.ingestion.parser import parse

        with tempfile.TemporaryDirectory() as tmp:
            path = make_synthetic_docx(Path(tmp))
            doc = parse(path, vendor_id="v1")

        table_blocks = [b for b in doc.blocks if b.source == "table_cell"]
        assert len(table_blocks) > 0


class TestXLSXParsing:
    def setup_method(self) -> None:
        _set_env()

    def test_parse_synthetic_xlsx(self) -> None:
        from tests.fixtures.make_xlsx import make_synthetic_xlsx
        from tprm.ingestion.parser import parse

        with tempfile.TemporaryDirectory() as tmp:
            path = make_synthetic_xlsx(Path(tmp))
            doc = parse(path, vendor_id="vendor-test")

        assert isinstance(doc, Document)
        assert doc.meta.doc_format == "xlsx"
        assert len(doc.blocks) > 0

    def test_xlsx_hidden_sheet_flagged(self) -> None:
        from tests.fixtures.make_xlsx import make_synthetic_xlsx
        from tprm.ingestion.parser import parse

        with tempfile.TemporaryDirectory() as tmp:
            path = make_synthetic_xlsx(Path(tmp))
            doc = parse(path, vendor_id="v1")

        assert doc.meta.has_hidden_sheets is True

    def test_xlsx_cell_section_path_has_sheet_name(self) -> None:
        from tests.fixtures.make_xlsx import make_synthetic_xlsx
        from tprm.ingestion.parser import parse

        with tempfile.TemporaryDirectory() as tmp:
            path = make_synthetic_xlsx(Path(tmp))
            doc = parse(path, vendor_id="v1")

        cell_blocks = [b for b in doc.blocks if b.source == "table_cell"]
        assert any(len(b.section_path) >= 1 for b in cell_blocks)


class TestSegmenter:
    def setup_method(self) -> None:
        _set_env()

    def test_section_paths_assigned(self) -> None:
        from tests.fixtures.make_pdf import make_synthetic_pdf
        from tprm.ingestion.parser import parse

        with tempfile.TemporaryDirectory() as tmp:
            path = make_synthetic_pdf(Path(tmp))
            doc = parse(path, vendor_id="v1")

        # At least some blocks should have non-empty section_path
        # (headings get added during segmentation)
        has_paths = any(len(b.section_path) > 0 for b in doc.blocks)
        assert has_paths
