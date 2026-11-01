"""Behavioural contracts for the signer port; a KMS signer (D11-11) reuses them.

Import with ``from signing.signer_contract import SignerContract, VerifierContract``.

``VerifierContract``: what a verify-only object (a broker's) must do. Fixtures:

* ``verifier``: the object under test.
* ``signer``: a ``Signer`` whose signatures ``verifier`` must accept (same key).
* ``foreign_signer``: a ``Signer`` with different key material; its key ID may differ.
* ``failing_verifier``: a ``Verifier`` whose backend fails transiently (throttle, timeout).

``SignerContract`` adds what a signer must do. ``verifier`` defaults to ``signer``. Extra fixture:

* ``failing_signer``: a ``Signer`` whose backend fails transiently on ``sign`` and ``verify``.

Set ``asymmetric = True`` on a subclass whose ``signer`` publishes public keys.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from sto.domain.errors import TransientError
from sto.signing.port import Signature, Signer, SigningError, Verifier


class VerifierContract:
    asymmetric = False

    @pytest.fixture
    def verifier(self) -> Verifier:
        raise NotImplementedError

    @pytest.fixture
    def signer(self) -> Signer:
        raise NotImplementedError

    @pytest.fixture
    def foreign_signer(self) -> Signer:
        raise NotImplementedError

    @pytest.fixture
    def failing_verifier(self) -> Verifier:
        raise NotImplementedError

    def test_satisfies_protocol(self, verifier: Verifier) -> None:
        assert isinstance(verifier, Verifier)

    def test_accepts_signers_signature(self, verifier: Verifier, signer: Signer) -> None:
        assert verifier.verify(b"payload", signer.sign(b"payload"))

    def test_rejects_tampered_message(self, verifier: Verifier, signer: Signer) -> None:
        assert not verifier.verify(b"payload!", signer.sign(b"payload"))

    def test_rejects_tampered_signature(self, verifier: Verifier, signer: Signer) -> None:
        sig = signer.sign(b"payload")
        flipped = bytes([sig.value[0] ^ 1]) + sig.value[1:]
        assert not verifier.verify(b"payload", dataclasses.replace(sig, value=flipped))

    def test_rejects_other_key_id(self, verifier: Verifier, signer: Signer) -> None:
        sig = signer.sign(b"m")
        assert not verifier.verify(b"m", dataclasses.replace(sig, key_id=sig.key_id + "-x"))

    def test_rejects_wrong_algorithm(self, verifier: Verifier, signer: Signer) -> None:
        sig = signer.sign(b"m")
        other = "RS256" if sig.algorithm != "RS256" else "HS256"
        assert not verifier.verify(b"m", dataclasses.replace(sig, algorithm=other))

    def test_rejects_other_key_material_under_our_key_id(
        self, verifier: Verifier, signer: Signer, foreign_signer: Signer
    ) -> None:
        sig = foreign_signer.sign(b"m")
        passed_off = dataclasses.replace(sig, key_id=signer.key_id, algorithm=signer.algorithm)
        assert not verifier.verify(b"m", passed_off)

    def test_transient_backend_failure_raises_transient_never_false(
        self, failing_verifier: Verifier, signer: Signer
    ) -> None:
        with pytest.raises(TransientError):
            failing_verifier.verify(b"m", signer.sign(b"m"))

    @pytest.mark.parametrize("bad", ["text", None, 5])
    def test_rejects_non_bytes_message(self, verifier: Verifier, signer: Signer, bad: Any) -> None:
        with pytest.raises(SigningError):
            verifier.verify(bad, signer.sign(b"m"))

    @pytest.mark.parametrize("bad", [None, "k.HS256.AAAA", b"x"])
    def test_rejects_non_signature(self, verifier: Verifier, bad: Any) -> None:
        with pytest.raises(SigningError):
            verifier.verify(b"m", bad)

    def test_public_keys_are_jwks_shaped(self, verifier: Verifier) -> None:
        for key in verifier.public_keys():
            assert {"kid", "kty", "alg"} <= set(key)

    def test_public_keys_published_only_when_asymmetric(
        self, verifier: Verifier, signer: Signer
    ) -> None:
        keys = verifier.public_keys()
        if not self.asymmetric:
            assert list(keys) == []
            return
        match = [k for k in keys if k["kid"] == signer.key_id]
        assert len(match) == 1
        assert match[0]["alg"] == signer.algorithm
        if match[0]["kty"] == "RSA":
            assert match[0]["n"]
            assert match[0]["e"]


class SignerContract(VerifierContract):
    @pytest.fixture
    def verifier(self, signer: Signer) -> Verifier:
        return signer

    @pytest.fixture
    def failing_signer(self) -> Signer:
        raise NotImplementedError

    def test_satisfies_protocols(self, signer: Signer) -> None:
        assert isinstance(signer, Signer)
        assert isinstance(signer, Verifier)

    def test_sign_verify_round_trip(self, signer: Signer) -> None:
        assert signer.verify(b"payload", signer.sign(b"payload"))

    def test_result_carries_key_id_and_algorithm(self, signer: Signer) -> None:
        sig = signer.sign(b"x")
        assert sig.key_id == signer.key_id
        assert sig.algorithm == signer.algorithm

    def test_algorithm_is_jose_name(self, signer: Signer) -> None:
        assert signer.algorithm in {"HS256", "RS256"}

    def test_wire_round_trip(self, signer: Signer) -> None:
        sig = signer.sign(b"m")
        decoded = Signature.decode(sig.encode())
        assert decoded == sig
        assert signer.verify(b"m", decoded)

    def test_sign_transient_failure_raises_transient(self, failing_signer: Signer) -> None:
        with pytest.raises(TransientError):
            failing_signer.sign(b"m")

    def test_sign_verify_transient_failure_raises_transient(
        self, failing_signer: Signer, signer: Signer
    ) -> None:
        with pytest.raises(TransientError):
            failing_signer.verify(b"m", signer.sign(b"m"))
