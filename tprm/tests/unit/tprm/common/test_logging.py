"""Unit tests for common/logging.py — PII scrubbing processor."""

from __future__ import annotations

import pytest
import structlog

from tprm.common.logging import configure_logging


class TestPIIScrubbing:
    """Test the _scrub_pii structlog processor directly."""

    def _scrub(self, event_dict: dict) -> dict:  # type: ignore[type-arg]
        """Call _scrub_pii with the correct 3-arg structlog signature."""
        from tprm.common.logging import _scrub_pii
        return _scrub_pii(None, "info", event_dict)  # type: ignore[arg-type]

    def test_scrubs_email(self) -> None:
        result = self._scrub({"event": "Processing user@example.com for block b1"})
        assert "user@example.com" not in result["event"]
        assert "[SCRUBBED:EMAIL]" in result["event"]

    def test_scrubs_credit_card(self) -> None:
        result = self._scrub({"event": "Card number 4111-1111-1111-1111 processed"})
        assert "4111-1111-1111-1111" not in result["event"]
        assert "[SCRUBBED:CREDIT_CARD]" in result["event"]

    def test_scrubs_ssn(self) -> None:
        result = self._scrub({"message": "SSN 123-45-6789 found in block"})
        assert "123-45-6789" not in result["message"]

    def test_scrubs_api_key_aws(self) -> None:
        result = self._scrub({"event": "Key AKIAIOSFODNN7EXAMPLE found"})
        assert "AKIAIOSFODNN7EXAMPLE" not in result["event"]
        assert "[SCRUBBED:API_KEY]" in result["event"]

    def test_scrubs_pem_header(self) -> None:
        result = self._scrub({"event": "-----BEGIN RSA PRIVATE KEY----- found in document"})
        assert "BEGIN RSA PRIVATE KEY" not in result["event"]
        assert "[SCRUBBED:PEM_KEY]" in result["event"]

    def test_scrubs_ip_address(self) -> None:
        result = self._scrub({"event": "Host 192.168.1.100 is internal"})
        assert "192.168.1.100" not in result["event"]
        assert "[SCRUBBED:IP_ADDRESS]" in result["event"]

    def test_preserves_safe_content(self) -> None:
        result = self._scrub({"event": "Stage gate passed successfully", "block_id": "abc-123"})
        assert result["event"] == "Stage gate passed successfully"
        assert result["block_id"] == "abc-123"

    def test_scrubs_nested_dict(self) -> None:
        result = self._scrub({
            "event": "ok",
            "context": {"field": "user@test.com is here"},
        })
        assert "user@test.com" not in result["context"]["field"]

    def test_non_string_values_unchanged(self) -> None:
        result = self._scrub({"event": "ok", "count": 42, "flag": True})
        assert result["count"] == 42
        assert result["flag"] is True

    def test_vault_token_scrubbed(self) -> None:
        result = self._scrub({"event": "Token <<EMAIL_ADDRESS_abc12345>> referenced"})
        assert "<<EMAIL_ADDRESS_abc12345>>" not in result["event"]

    def test_configure_logging_runs_without_error(self) -> None:
        from tprm.common.logging import configure_logging
        configure_logging(level="DEBUG", json_logs=False)
