"""Token vault: stores Fernet-encrypted original values keyed by deterministic tokens.

The vault is backed by an in-memory dict for now (real impl would use Postgres).
Detokenization is disabled by default and requires TPRM_ALLOW_DETOKENIZE=true.
"""

from __future__ import annotations

import os
from typing import Any

from tprm.common.crypto import fernet_decrypt, fernet_encrypt, load_vault_key
from tprm.common.errors import DetokenizationDisabled, VaultError
from tprm.common.logging import get_logger

log = get_logger(__name__)


class TokenVault:
    """In-memory token vault (production would use PostgreSQL + asyncpg).

    All values stored as Fernet ciphertext.
    Detokenization requires TPRM_ALLOW_DETOKENIZE=true env var.
    """

    def __init__(self, vault_key: bytes | None = None) -> None:
        self._key = vault_key or load_vault_key()
        # {assessment_id: {token: ciphertext}}
        self._store: dict[str, dict[str, bytes]] = {}
        # {assessment_id: {token: entity_type}}
        self._types: dict[str, dict[str, str]] = {}

    def store(
        self,
        token: str,
        raw_value: str,
        entity_type: str,
        assessment_id: str,
    ) -> None:
        """Encrypt and store ``raw_value`` under ``token`` for ``assessment_id``."""
        try:
            ciphertext = fernet_encrypt(raw_value, self._key)
        except Exception as exc:
            raise VaultError(f"Failed to encrypt vault entry: {exc}") from exc

        if assessment_id not in self._store:
            self._store[assessment_id] = {}
            self._types[assessment_id] = {}

        self._store[assessment_id][token] = ciphertext
        self._types[assessment_id][token] = entity_type
        # Never log raw_value
        log.debug("vault_store", assessment_id=assessment_id, entity_type=entity_type)

    def lookup_raw_values(self, assessment_id: str) -> list[str]:
        """Return all raw values for an assessment (for gate vault check).

        Used by the Security Gate to verify no raw value appears in output.
        This is the only legitimate use of decryption outside detokenization.
        """
        if assessment_id not in self._store:
            return []
        result: list[str] = []
        for token, ciphertext in self._store[assessment_id].items():
            try:
                raw = fernet_decrypt(ciphertext, self._key)
                result.append(raw)
            except VaultError:
                log.warning("vault_decrypt_failed_during_lookup", assessment_id=assessment_id)
        return result

    def detokenize(
        self,
        token: str,
        assessment_id: str,
        reason: str = "",
    ) -> str:
        """Return the original value for a token.

        Requires TPRM_ALLOW_DETOKENIZE=true env var.
        Writes an audit entry on every call.
        """
        if not os.environ.get("TPRM_ALLOW_DETOKENIZE", "false").lower() == "true":
            raise DetokenizationDisabled(
                "Detokenization is disabled. Set TPRM_ALLOW_DETOKENIZE=true to enable."
            )

        if not reason:
            raise VaultError("Detokenization requires a non-empty reason string")

        ciphertext = self._store.get(assessment_id, {}).get(token)
        if ciphertext is None:
            raise VaultError(f"Token not found in vault for assessment {assessment_id!r}")

        raw = fernet_decrypt(ciphertext, self._key)
        # Audit: log access (token only, not the raw value)
        log.info(
            "vault_detokenize",
            assessment_id=assessment_id,
            token=token,
            reason=reason,
            # raw value NEVER logged
        )
        return raw

    def token_count(self, assessment_id: str) -> int:
        """Return number of stored tokens for an assessment."""
        return len(self._store.get(assessment_id, {}))

    def has_token(self, token: str, assessment_id: str) -> bool:
        """Return True if token exists for assessment."""
        return token in self._store.get(assessment_id, {})


# Module-level singleton
_vault_instance: TokenVault | None = None


def get_vault() -> TokenVault:
    """Return the module-level vault singleton."""
    global _vault_instance  # noqa: PLW0603
    if _vault_instance is None:
        _vault_instance = TokenVault()
    return _vault_instance


def reset_vault() -> None:
    """Reset vault singleton (for testing only)."""
    global _vault_instance  # noqa: PLW0603
    _vault_instance = None
