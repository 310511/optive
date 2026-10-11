"""Global test configuration and fixtures."""

from __future__ import annotations

import os

import pytest

# Set required env vars before any imports
_TEST_VAULT_KEY = "j5yCD74TW57pnqdPTzy_qHDrAjXX89hdQwdpM4Bf0l8="
_TEST_GATE_KEY = "test-gate-key"

os.environ.setdefault("TPRM_VAULT_KEY", _TEST_VAULT_KEY)
os.environ.setdefault("GATE_SIGNING_KEY", _TEST_GATE_KEY)


@pytest.fixture(autouse=True)
def reset_singletons() -> None:
    """Reset all module-level singletons between tests to prevent state leakage."""
    # Pre-test: set required env vars and clear singletons
    os.environ["TPRM_VAULT_KEY"] = _TEST_VAULT_KEY
    os.environ["GATE_SIGNING_KEY"] = _TEST_GATE_KEY
    # Don't set TPRM_ALLOW_DETOKENIZE by default
    os.environ.pop("TPRM_ALLOW_DETOKENIZE", None)

    # Clear Settings cache
    try:
        from tprm.common.config import get_settings
        get_settings.cache_clear()
    except Exception:
        pass

    # Clear vault singleton
    try:
        from tprm.sanitize.vault import reset_vault
        reset_vault()
    except Exception:
        pass

    # Clear PII detector singleton
    try:
        from tprm.pii.detector import reset_analyzer
        reset_analyzer()
    except Exception:
        pass

    # Clear audit log singleton
    try:
        from tprm.common.audit import reset_audit_log
        reset_audit_log()
    except Exception:
        pass

    # Clear gate analyzer singleton
    try:
        from tprm.gate.gate import reset_gate_analyzer
        reset_gate_analyzer()
    except Exception:
        pass

    yield  # type: ignore[misc]

    # Post-test cleanup (same as pre-test)
    try:
        from tprm.common.config import get_settings
        get_settings.cache_clear()
    except Exception:
        pass
    try:
        from tprm.sanitize.vault import reset_vault
        reset_vault()
    except Exception:
        pass
