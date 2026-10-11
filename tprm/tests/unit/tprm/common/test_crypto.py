"""Unit tests for common/crypto.py."""

from __future__ import annotations

import os

import pytest

from tprm.common.crypto import (
    derive_assessment_salt,
    derive_token,
    fernet_decrypt,
    fernet_encrypt,
    generate_fernet_key,
    hmac_sign,
    hmac_verify,
    max_window_entropy,
    shannon_entropy,
)
from tprm.common.errors import VaultError


class TestFernet:
    def _key(self) -> bytes:
        return generate_fernet_key().encode()

    def test_round_trip(self) -> None:
        key = self._key()
        plaintext = "sensitive-value-12345"
        ct = fernet_encrypt(plaintext, key)
        assert fernet_decrypt(ct, key) == plaintext

    def test_ciphertext_not_plaintext(self) -> None:
        key = self._key()
        plaintext = "do-not-leak-this"
        ct = fernet_encrypt(plaintext, key)
        assert plaintext.encode() not in ct

    def test_wrong_key_raises(self) -> None:
        key1 = self._key()
        key2 = self._key()
        ct = fernet_encrypt("secret", key1)
        with pytest.raises(VaultError):
            fernet_decrypt(ct, key2)

    def test_tampered_ciphertext_raises(self) -> None:
        key = self._key()
        ct = fernet_encrypt("secret", key)
        tampered = bytearray(ct)
        tampered[10] ^= 0xFF  # flip bits
        with pytest.raises(VaultError):
            fernet_decrypt(bytes(tampered), key)


class TestHMAC:
    def test_sign_and_verify(self) -> None:
        key = b"test-signing-key"
        data = b"payload to sign"
        sig = hmac_sign(data, key)
        assert hmac_verify(data, key, sig)

    def test_wrong_key_fails(self) -> None:
        sig = hmac_sign(b"data", b"key1")
        assert not hmac_verify(b"data", b"key2", sig)

    def test_tampered_data_fails(self) -> None:
        key = b"key"
        sig = hmac_sign(b"original", key)
        assert not hmac_verify(b"tampered", key, sig)

    def test_returns_hex_string(self) -> None:
        sig = hmac_sign(b"data", b"key")
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)


class TestTokenDerivation:
    def test_deterministic_within_assessment(self) -> None:
        token1 = derive_token("john.doe@example.com", "EMAIL_ADDRESS", "salt-abc")
        token2 = derive_token("john.doe@example.com", "EMAIL_ADDRESS", "salt-abc")
        assert token1 == token2

    def test_non_deterministic_across_assessments(self) -> None:
        token1 = derive_token("john.doe@example.com", "EMAIL_ADDRESS", "salt-abc")
        token2 = derive_token("john.doe@example.com", "EMAIL_ADDRESS", "salt-xyz")
        assert token1 != token2

    def test_different_entities_different_tokens(self) -> None:
        t1 = derive_token("alice@example.com", "EMAIL_ADDRESS", "salt")
        t2 = derive_token("bob@example.com", "EMAIL_ADDRESS", "salt")
        assert t1 != t2

    def test_token_format(self) -> None:
        token = derive_token("test@example.com", "EMAIL_ADDRESS", "salt")
        assert token.startswith("<<EMAIL_ADDRESS_")
        assert token.endswith(">>")
        # Token suffix is 8 hex chars
        suffix = token[len("<<EMAIL_ADDRESS_") : -2]
        assert len(suffix) == 8
        assert all(c in "0123456789abcdef" for c in suffix)

    def test_raw_value_not_in_token(self) -> None:
        email = "supersecret@corp.internal"
        token = derive_token(email, "EMAIL_ADDRESS", "salt")
        assert email not in token
        assert "supersecret" not in token

    def test_assessment_salt_derivation(self) -> None:
        master = b"master-key-bytes"
        s1 = derive_assessment_salt("vendor-a", "assess-1", master)
        s2 = derive_assessment_salt("vendor-a", "assess-1", master)
        s3 = derive_assessment_salt("vendor-b", "assess-1", master)
        assert s1 == s2          # same inputs → same salt
        assert s1 != s3          # different vendor → different salt


class TestEntropy:
    def test_all_same_char_zero_entropy(self) -> None:
        assert shannon_entropy("aaaaaaa") == pytest.approx(0.0)

    def test_high_entropy_random(self) -> None:
        # Random-looking API key should have high entropy
        api_key = "AKIAIOSFODNN7EXAMPLE"
        assert shannon_entropy(api_key) > 3.5

    def test_low_entropy_word(self) -> None:
        assert shannon_entropy("hello") < 2.5

    def test_window_entropy_catches_high_entropy_substring(self) -> None:
        # Normal text with an embedded high-entropy API key
        text = "The key is: AKIAIOSFODNN7EXAMPLEKEY1234567890AB and more text here"
        entropy = max_window_entropy(text, window=20)
        assert entropy > 4.0

    def test_empty_string_zero_entropy(self) -> None:
        assert shannon_entropy("") == 0.0
        assert max_window_entropy("") == 0.0
