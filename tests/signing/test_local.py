"""LocalSigner: the shared contract plus rotation, configuration and no-leak behaviour."""

from __future__ import annotations

import copy
import logging
import pickle
from typing import Any

import pytest
from signer_contract import SignerContract

from sto.signing.local import LocalSigner
from sto.signing.port import SigningError, Verifier

SECRET = b"s3cret-key-material-0123456789abcdef"
OLD = b"0ld-retired-key-material-0123456789ab"


class TestLocalSignerContract(SignerContract):
    @pytest.fixture
    def signer(self) -> LocalSigner:
        return LocalSigner(key_id="k1", secret=SECRET)

    @pytest.fixture
    def foreign_signer(self) -> LocalSigner:
        return LocalSigner(key_id="k1", secret=SECRET[::-1])


def test_reports_jose_name() -> None:
    assert LocalSigner(key_id="k", secret=SECRET).algorithm == "HS256"


def test_symmetric_key_has_no_public_keys() -> None:
    assert list(LocalSigner(key_id="k", secret=SECRET).public_keys()) == []


def test_new_key_signs_and_retired_key_still_verifies() -> None:
    old = LocalSigner(key_id="old", secret=OLD)
    new = LocalSigner(key_id="new", secret=SECRET, retired={"old": OLD})
    assert new.verify(b"m", old.sign(b"m"))
    assert new.sign(b"m").key_id == "new"


def test_verifier_with_only_old_key_rejects_new_signatures() -> None:
    old = LocalSigner(key_id="old", secret=OLD)
    new = LocalSigner(key_id="new", secret=SECRET, retired={"old": OLD})
    assert not old.verify(b"m", new.sign(b"m"))


def test_retired_key_with_wrong_material_rejected() -> None:
    forged = LocalSigner(key_id="old", secret=SECRET)
    new = LocalSigner(key_id="new", secret=SECRET[::-1], retired={"old": OLD})
    assert not new.verify(b"m", forged.sign(b"m"))


def test_usable_as_verifier() -> None:
    v: Verifier = LocalSigner(key_id="k", secret=SECRET)
    assert v.verify(b"m", LocalSigner(key_id="k", secret=SECRET).sign(b"m"))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key_id": "k", "secret": b"short"},
        {"key_id": "", "secret": SECRET},
        {"key_id": "k", "secret": SECRET.decode()},
        {"key_id": "k", "secret": None},
        {"key_id": None, "secret": SECRET},
        {"key_id": "k", "secret": SECRET, "retired": {"k": OLD}},
        {"key_id": "k", "secret": SECRET, "retired": {"r": b"short"}},
        {"key_id": "k", "secret": SECRET, "retired": {"r": OLD.decode()}},
        {"key_id": "k", "secret": SECRET, "retired": {"": OLD}},
    ],
)
def test_bad_configuration_refused_at_construction(kwargs: dict[str, Any]) -> None:
    with pytest.raises(SigningError):
        LocalSigner(**kwargs)


def test_sign_rejects_non_bytes() -> None:
    with pytest.raises(SigningError):
        LocalSigner(key_id="k", secret=SECRET).sign("text")  # type: ignore[arg-type]


def _leak_forms(*secrets: bytes) -> list[str]:
    import base64

    forms: list[str] = []
    for s in secrets:
        forms += [
            s.decode(),
            s.hex(),
            s.hex().upper(),
            base64.b64encode(s).decode(),
            base64.urlsafe_b64encode(s).decode(),
            repr(s),
        ]
    return forms


def test_no_private_key_in_logs_repr_or_errors(caplog: pytest.LogCaptureFixture) -> None:
    errors: list[str] = []
    with caplog.at_level(logging.DEBUG):
        signer = LocalSigner(key_id="k", secret=SECRET, retired={"old": OLD})
        sig = signer.sign(b"m")
        signer.verify(b"m", sig)
        signer.verify(b"m2", sig)
        for bad in (
            lambda: LocalSigner(key_id="k", secret=b"short" + SECRET[:3]),
            lambda: LocalSigner(key_id="", secret=SECRET),
            lambda: LocalSigner(key_id="k", secret=SECRET.decode()),  # type: ignore[arg-type]
            lambda: LocalSigner(key_id="k", secret=SECRET, retired={"k": OLD}),
            lambda: LocalSigner(key_id="k", secret=SECRET, retired={"r": OLD[:5]}),
            lambda: LocalSigner(key_id="k", secret=SECRET, retired={"r": OLD.decode()}),  # type: ignore[dict-item]
            lambda: pickle.dumps(signer),
            lambda: copy.copy(signer),
            lambda: copy.deepcopy(signer),
            lambda: signer.sign("m"),  # type: ignore[arg-type]
        ):
            with pytest.raises(SigningError) as exc:
                bad()
            errors.append(str(exc.value) + repr(exc.value))
    haystack = "\n".join([caplog.text, repr(signer), str(signer), *errors, repr(sig)])
    for form in _leak_forms(SECRET, OLD):
        assert form not in haystack


def test_repr_shows_key_ids_only() -> None:
    text = repr(LocalSigner(key_id="current", secret=SECRET, retired={"retired-1": OLD}))
    assert "current" in text
    assert "retired-1" in text


def test_secret_not_in_vars() -> None:
    signer = LocalSigner(key_id="k", secret=SECRET)
    assert not hasattr(signer, "__dict__")


@pytest.mark.parametrize("op", [pickle.dumps, copy.copy, copy.deepcopy])
def test_pickle_and_copy_blocked(op: Any) -> None:
    with pytest.raises(SigningError):
        op(LocalSigner(key_id="k", secret=SECRET))
