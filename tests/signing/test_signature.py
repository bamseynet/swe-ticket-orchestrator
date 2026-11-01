"""Signature value type: construction and strict, canonical text form."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from sto.domain.errors import PermanentError
from sto.signing.port import Signature, SigningError

# 0xfb 0xff encodes with "-_" in base64url ("+/" in the standard alphabet)
GOOD = Signature(key_id="k", algorithm="HS256", value=b"\xfb\xff" + bytes(range(30)))


def test_round_trip() -> None:
    assert Signature.decode(GOOD.encode()) == GOOD


def test_round_trip_dotted_key_id() -> None:
    sig = Signature(key_id="prod.2026.11", algorithm="RS256", value=b"\x01\x02\x03")
    assert Signature.decode(sig.encode()) == sig


def test_signing_error_is_permanent() -> None:
    assert issubclass(SigningError, PermanentError)
    assert SigningError("x").failure_class.value == "permanent"


def test_encoding_is_unpadded_urlsafe() -> None:
    text = Signature(key_id="k", algorithm="HS256", value=b"\xfb\xff").encode()
    assert text == "k.HS256.-_8"


def _mutations() -> list[str]:
    good = GOOD.encode()
    b64 = good.split(".")[2]
    std = base64.b64encode(GOOD.value).decode().rstrip("=")  # + and / alphabet
    assert std != b64
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    # 32 bytes = 43 chars; the last char has 2 spare bits, so flipping the lowest one still
    # decodes to the same bytes in a lenient decoder
    altered_bits = b64[:-1] + alphabet[alphabet.index(b64[-1]) ^ 1]
    return [
        "k.HS256.!!!!",  # invalid alphabet, would decode to empty
        "k.HS256.",  # empty value
        good + "!!",  # appended junk
        good + "=",  # padding is not canonical
        good + "AA",  # impossible length (45 chars)
        f"k.HS256.{std}",  # standard alphabet
        f"k.HS256.{altered_bits}",  # altered trailing bits
        "nodots",
        "k.HS256",
        ".HS256.AAAA",
        "k..AAAA",
        "",
    ]


@pytest.mark.parametrize("text", _mutations())
def test_decode_rejects_non_canonical(text: str) -> None:
    with pytest.raises(SigningError):
        Signature.decode(text)


@pytest.mark.parametrize("bad", [None, 5, b"k.HS256.AAAA"])
def test_decode_rejects_non_str(bad: Any) -> None:
    with pytest.raises(SigningError):
        Signature.decode(bad)


def test_dotted_algorithm_refused_at_construction() -> None:
    with pytest.raises(SigningError):
        Signature(key_id="k", algorithm="RS.256", value=b"x")


@pytest.mark.parametrize(
    ("key_id", "algorithm", "value"),
    [("", "HS256", b"x"), ("k", "", b"x"), ("k", "HS256", b""), ("k", "HS256", "str")],
)
def test_invalid_fields_refused(key_id: str, algorithm: str, value: Any) -> None:
    with pytest.raises(SigningError):
        Signature(key_id=key_id, algorithm=algorithm, value=value)
