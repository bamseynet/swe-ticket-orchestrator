"""Behavioural contract every ``Signer`` must pass; a KMS signer (D11-11) reuses it.

Subclass ``SignerContract`` in a ``Test*`` class and provide two fixtures: ``signer``, and
``foreign_signer``, which has the same key ID as ``signer`` but different key material.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from sto.signing.port import Signature, Signer, SigningError, Verifier


class SignerContract:
    @pytest.fixture
    def signer(self) -> Signer:
        raise NotImplementedError

    @pytest.fixture
    def foreign_signer(self) -> Signer:
        raise NotImplementedError

    def test_satisfies_protocols(self, signer: Signer) -> None:
        assert isinstance(signer, Signer)
        assert isinstance(signer, Verifier)

    def test_sign_verify_round_trip(self, signer: Signer) -> None:
        assert signer.verify(b"payload", signer.sign(b"payload"))

    def test_rejects_tampered_message(self, signer: Signer) -> None:
        assert not signer.verify(b"payload!", signer.sign(b"payload"))

    def test_rejects_tampered_signature(self, signer: Signer) -> None:
        sig = signer.sign(b"payload")
        flipped = bytes([sig.value[0] ^ 1]) + sig.value[1:]
        assert not signer.verify(b"payload", dataclasses.replace(sig, value=flipped))

    def test_result_carries_key_id_and_algorithm(self, signer: Signer) -> None:
        sig = signer.sign(b"x")
        assert sig.key_id == signer.key_id
        assert sig.algorithm == signer.algorithm

    def test_algorithm_is_jose_name_without_dots(self, signer: Signer) -> None:
        assert signer.algorithm in {"HS256", "RS256", "ES256", "PS256"}

    def test_rejects_other_key_id(self, signer: Signer) -> None:
        sig = signer.sign(b"m")
        assert not signer.verify(b"m", dataclasses.replace(sig, key_id=sig.key_id + "-x"))

    def test_rejects_wrong_algorithm(self, signer: Signer) -> None:
        sig = signer.sign(b"m")
        other = "RS256" if sig.algorithm != "RS256" else "HS256"
        assert not signer.verify(b"m", dataclasses.replace(sig, algorithm=other))

    def test_rejects_signature_from_other_key_material(
        self, signer: Signer, foreign_signer: Signer
    ) -> None:
        assert signer.key_id == foreign_signer.key_id
        assert not signer.verify(b"m", foreign_signer.sign(b"m"))

    def test_wire_round_trip(self, signer: Signer) -> None:
        sig = signer.sign(b"m")
        decoded = Signature.decode(sig.encode())
        assert decoded == sig
        assert signer.verify(b"m", decoded)

    def test_public_keys_are_jwks_shaped(self, signer: Signer) -> None:
        for key in signer.public_keys():
            assert {"kid", "kty", "alg"} <= set(key)
            assert key["alg"] == signer.algorithm

    @pytest.mark.parametrize("bad", ["text", None, 5])
    def test_verify_rejects_non_bytes_message(self, signer: Signer, bad: Any) -> None:
        with pytest.raises(SigningError):
            signer.verify(bad, signer.sign(b"m"))

    @pytest.mark.parametrize("bad", [None, "k.HS256.AAAA", b"x"])
    def test_verify_rejects_non_signature(self, signer: Signer, bad: Any) -> None:
        with pytest.raises(SigningError):
            signer.verify(b"m", bad)
