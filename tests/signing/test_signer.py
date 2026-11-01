"""Signer port: round-trip, key ID for rotation, and no key material in logs or reprs."""

from __future__ import annotations

import logging

import pytest

from sto.signing.local import LocalSigner
from sto.signing.port import Signer, SigningError

SECRET = b"s3cret-key-material-0123456789abcdef"


def test_sign_verify_round_trip() -> None:
    signer: Signer = LocalSigner(key_id="k1", secret=SECRET)
    sig = signer.sign(b"payload")
    assert signer.verify(b"payload", sig)


def test_verify_rejects_tampered_message() -> None:
    signer = LocalSigner(key_id="k1", secret=SECRET)
    sig = signer.sign(b"payload")
    assert not signer.verify(b"payload!", sig)


def test_verify_rejects_tampered_signature() -> None:
    signer = LocalSigner(key_id="k1", secret=SECRET)
    sig = signer.sign(b"payload")
    bad = type(sig)(key_id=sig.key_id, algorithm=sig.algorithm, value=b"\x00" * len(sig.value))
    assert not signer.verify(b"payload", bad)


def test_result_carries_key_id_and_algorithm() -> None:
    sig = LocalSigner(key_id="2026-11", secret=SECRET).sign(b"x")
    assert sig.key_id == "2026-11"
    assert sig.algorithm == "HMAC-SHA256"


def test_signature_from_other_key_id_is_rejected() -> None:
    old = LocalSigner(key_id="old", secret=SECRET)
    new = LocalSigner(key_id="new", secret=SECRET)
    assert not new.verify(b"m", old.sign(b"m"))


def test_different_secret_does_not_verify() -> None:
    a = LocalSigner(key_id="k", secret=SECRET)
    b = LocalSigner(key_id="k", secret=SECRET + b"x")
    assert not b.verify(b"m", a.sign(b"m"))


def test_rotation_verifier_accepts_retired_key() -> None:
    old = LocalSigner(key_id="old", secret=b"o" * 32)
    new = LocalSigner(key_id="new", secret=b"n" * 32, retired={"old": b"o" * 32})
    assert new.verify(b"m", old.sign(b"m"))
    assert new.sign(b"m").key_id == "new"


def test_signature_wire_round_trip() -> None:
    signer = LocalSigner(key_id="k", secret=SECRET)
    sig = signer.sign(b"m")
    assert type(sig).decode(sig.encode()) == sig


def test_decode_rejects_malformed() -> None:
    from sto.signing.port import Signature

    with pytest.raises(SigningError):
        Signature.decode("not-a-signature")


def test_short_secret_refused() -> None:
    with pytest.raises(SigningError):
        LocalSigner(key_id="k", secret=b"short")


def test_empty_key_id_refused() -> None:
    with pytest.raises(SigningError):
        LocalSigner(key_id="", secret=SECRET)


def test_no_private_key_in_repr_or_str() -> None:
    signer = LocalSigner(key_id="k", secret=SECRET, retired={"r": b"r" * 32})
    for text in (repr(signer), str(signer)):
        assert SECRET.decode() not in text
        assert "rrrr" not in text
        assert "k" in text


def test_no_private_key_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        signer = LocalSigner(key_id="k", secret=SECRET)
        sig = signer.sign(b"m")
        signer.verify(b"m", sig)
        signer.verify(b"m2", sig)
    assert SECRET.decode() not in caplog.text
    assert SECRET.hex() not in caplog.text


def test_no_private_key_in_error_messages() -> None:
    with pytest.raises(SigningError) as exc:
        LocalSigner(key_id="", secret=SECRET)
    assert SECRET.decode() not in str(exc.value)


def test_signature_wire_round_trip_with_dotted_key_id() -> None:
    sig = LocalSigner(key_id="prod.2026.11", secret=SECRET).sign(b"m")
    assert type(sig).decode(sig.encode()) == sig
