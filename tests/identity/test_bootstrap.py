"""First org admin (D3-18): one way into an empty system, usable once."""

from __future__ import annotations

import pytest

from sto.config.org_policy import ORG_ADMIN, Principal
from sto.domain.errors import PermanentError
from sto.identity.bootstrap import Bootstrap, BootstrapRefusedError
from sto.identity.mapping import RoleMapping, UserDisabledError, UserIdentity
from sto.identity.oidc import VerifiedToken
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, Key

ISS = "https://idp.example.test"
NOW = 1_800_000_000.0
BOOT = "grp-bootstrap"
ADMINS = "grp-admins"
ORG = Principal("root", frozenset({ORG_ADMIN}))


def _tok(groups: list[str], sub: str = "u-1", iss: str = ISS, **claims: object) -> VerifiedToken:
    return VerifiedToken(
        subject=sub,
        issuer=iss,
        groups=tuple(groups),
        auth_time=NOW,
        expires_at=NOW + 900,
        claims={"sub": sub, **claims},
    )


class Env:
    def __init__(self) -> None:
        self.store = MemoryStore()
        self.mapping = RoleMapping(self.store, issuers=[ISS], clock=lambda: NOW)
        self.audit: list[dict[str, object]] = []
        self.boot = Bootstrap(
            self.store,
            self.mapping,
            idp=ISS,
            group=BOOT,
            clock=lambda: NOW,
            audit=self.audit.append,
        )


@pytest.fixture
def env() -> Env:
    return Env()


def test_empty_system_bootstrap_group_gets_in(env: Env) -> None:
    assert env.boot.is_open()
    who = env.boot.claim(_tok([BOOT]), admin_group=ADMINS)
    assert who.is_org_admin
    got = env.mapping.resolve(_tok([ADMINS], sub="u-2"))
    assert isinstance(got, UserIdentity)
    assert (None, ORG_ADMIN) in got.memberships


def test_default_admin_group_is_the_bootstrap_group(env: Env) -> None:
    env.boot.claim(_tok([BOOT]))
    assert env.mapping.mapping(ISS, BOOT) == (None, ORG_ADMIN)


@pytest.mark.parametrize(
    "token",
    [
        _tok(["other"]),
        _tok([]),
        _tok([BOOT.upper()]),
        _tok([BOOT + " "]),
        _tok([BOOT], iss="https://evil.example.test"),
        _tok([BOOT], sub="svc", client_id="svc"),
    ],
)
def test_only_the_named_group_in_the_named_issuer_is_a_way_in(
    env: Env, token: VerifiedToken
) -> None:
    with pytest.raises(BootstrapRefusedError):
        env.boot.claim(token, admin_group=ADMINS)
    assert env.boot.is_open()
    assert env.audit == []


def test_cannot_be_reused_after_it_worked(env: Env) -> None:
    env.boot.claim(_tok([BOOT]), admin_group=ADMINS)
    assert not env.boot.is_open()
    with pytest.raises(BootstrapRefusedError):
        env.boot.claim(_tok([BOOT], sub="u-3"), admin_group="grp-evil")
    assert env.mapping.mapping(ISS, "grp-evil") is None


def test_stays_closed_after_all_mappings_are_removed(env: Env) -> None:
    env.boot.claim(_tok([BOOT]), admin_group=ADMINS)
    env.mapping.remove_mapping(ORG, idp=ISS, group=ADMINS, team=None)
    assert not env.boot.is_open()
    with pytest.raises(BootstrapRefusedError):
        env.boot.claim(_tok([BOOT]), admin_group=ADMINS)


def test_closed_by_any_existing_mapping(env: Env) -> None:
    env.mapping.set_mapping(ORG, idp=ISS, group="g-x", team=None, role=ORG_ADMIN)
    assert not env.boot.is_open()
    with pytest.raises(BootstrapRefusedError):
        env.boot.claim(_tok([BOOT]), admin_group=ADMINS)
    assert env.mapping.mapping(ISS, ADMINS) is None


def test_disabled_user_cannot_bootstrap(env: Env) -> None:
    env.mapping.disable_user(ORG, idp=ISS, subject="u-1")
    # a disabled-user record is not a mapping, so the system is still empty
    with pytest.raises(UserDisabledError):
        env.boot.claim(_tok([BOOT]), admin_group=ADMINS)
    assert env.boot.is_open()


def test_use_is_audited(env: Env) -> None:
    env.boot.claim(_tok([BOOT]), admin_group=ADMINS)
    assert env.audit == [
        {
            "event": "bootstrap.claimed",
            "actor": f"{ISS}|u-1",
            "idp": ISS,
            "bootstrap_group": BOOT,
            "admin_group": ADMINS,
            "at": NOW,
        }
    ]
    marker = env.store.get(PLATFORM, Key("ORG", "BOOTSTRAP#USED"))
    assert marker is not None
    assert marker.data["by"] == f"{ISS}|u-1"


def test_bad_admin_group_is_refused_and_leaves_it_open(env: Env) -> None:
    with pytest.raises(PermanentError):
        env.boot.claim(_tok([BOOT]), admin_group=" bad ")
    assert env.boot.is_open()
    assert env.audit == []


def test_misconfigured_bootstrap_is_refused() -> None:
    store = MemoryStore()
    mapping = RoleMapping(store, issuers=[ISS])
    with pytest.raises(ValueError, match="configured issuer"):
        Bootstrap(store, mapping, idp="https://nope.example.test", group=BOOT)
    with pytest.raises(ValueError, match="non-empty"):
        Bootstrap(store, mapping, idp=ISS, group="")
