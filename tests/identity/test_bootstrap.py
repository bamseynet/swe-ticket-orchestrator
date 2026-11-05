"""First org admin (D3-18): one way into an empty system, usable once."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

import pytest

from sto.config.org_policy import ORG_ADMIN, Principal
from sto.identity.bootstrap import Bootstrap, BootstrapRefusedError, BootstrapRetryError
from sto.identity.mapping import RoleMapping, UserDisabledError, UserIdentity
from sto.identity.oidc import VerifiedToken
from sto.store.memory import MemoryStore
from sto.store.ports import (
    PLATFORM,
    ConditionFailedError,
    Key,
    Put,
    TransactionConflictError,
    TransactionOutcomeUnknownError,
)

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
    def __init__(self, store: MemoryStore | None = None) -> None:
        self.store = store or MemoryStore()
        self.mapping = RoleMapping(self.store, issuers=[ISS], clock=lambda: NOW)
        self.audit: list[dict[str, object]] = []
        self.boot = Bootstrap(
            self.mapping,
            idp=ISS,
            group=BOOT,
            clock=lambda: NOW,
            audit=self.audit.append,
        )


@pytest.fixture
def env() -> Env:
    return Env()


def _marker(env: Env) -> dict[str, object] | None:
    item = env.store.get(PLATFORM, Key("ORG", "BOOTSTRAP#USED"))
    return item.data if item else None


def test_empty_system_bootstrap_group_gets_in(env: Env) -> None:
    assert env.boot.is_open()
    who = env.boot.claim(_tok([BOOT]))
    assert who.is_org_admin
    got = env.mapping.resolve(_tok([BOOT], sub="u-2"))
    assert isinstance(got, UserIdentity)
    assert (None, ORG_ADMIN) in got.memberships


def test_mapping_written_is_the_configured_group_and_nothing_else(env: Env) -> None:
    env.boot.claim(_tok([BOOT, "grp-other"]))
    assert env.mapping.mapping(ISS, BOOT) == (None, ORG_ADMIN)
    assert env.mapping.mapping(ISS, "grp-other") is None
    keys = [i.key.sk for i in env.store.query(PLATFORM, "ORG").items]
    assert sorted(keys) == ["BOOTSTRAP#USED", f"MAP#{ISS}#{BOOT}"]


def test_claim_takes_no_admin_group(env: Env) -> None:
    with pytest.raises(TypeError):
        env.boot.claim(_tok([BOOT]), admin_group="grp-evil")  # type: ignore[call-arg]


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
        env.boot.claim(token)
    assert env.boot.is_open()
    assert env.audit == []


def test_cannot_be_reused_after_it_worked(env: Env) -> None:
    env.boot.claim(_tok([BOOT]))
    assert not env.boot.is_open()
    with pytest.raises(BootstrapRefusedError):
        env.boot.claim(_tok([BOOT], sub="u-3"))
    assert len(env.audit) == 1


def test_stays_closed_after_all_mappings_are_removed(env: Env) -> None:
    env.boot.claim(_tok([BOOT]))
    env.mapping.remove_mapping(ORG, idp=ISS, group=BOOT, team=None)
    assert not env.boot.is_open()
    with pytest.raises(BootstrapRefusedError):
        env.boot.claim(_tok([BOOT]))
    assert env.mapping.mapping(ISS, BOOT) is None


def test_mapping_written_through_role_mapping_closes_bootstrap(env: Env) -> None:
    """Fails if mapping.py's key layout drifts from the prefix this module queries."""
    env.mapping.set_mapping(ORG, idp=ISS, group="g-x", team=None, role=ORG_ADMIN)
    assert not env.boot.is_open()
    with pytest.raises(BootstrapRefusedError):
        env.boot.claim(_tok([BOOT]))
    assert env.mapping.mapping(ISS, BOOT) is None
    assert env.audit == []


def test_disabled_user_cannot_bootstrap(env: Env) -> None:
    env.mapping.disable_user(ORG, idp=ISS, subject="u-1")
    with pytest.raises(UserDisabledError):
        env.boot.claim(_tok([BOOT]))
    assert env.boot.is_open()


def test_use_is_audited_and_marker_is_the_durable_record(env: Env) -> None:
    env.boot.claim(_tok([BOOT]))
    record = {"by": f"{ISS}|u-1", "at": NOW, "idp": ISS, "group": BOOT}
    assert _marker(env) == record
    assert env.audit == [{"event": "bootstrap.claimed", **record}]


def test_audit_failure_after_commit_is_logged_and_claim_succeeds(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = MemoryStore()

    def boom(event: dict[str, object]) -> None:
        raise RuntimeError("audit sink down")

    env = Env(store)
    boot = Bootstrap(env.mapping, idp=ISS, group=BOOT, clock=lambda: NOW, audit=boom)
    with caplog.at_level(logging.ERROR):
        who = boot.claim(_tok([BOOT]))
    assert who.is_org_admin
    assert env.mapping.mapping(ISS, BOOT) == (None, ORG_ADMIN)
    assert _marker(env) is not None
    assert "audit callback failed" in caplog.text


def test_audit_is_required() -> None:
    store = MemoryStore()
    mapping = RoleMapping(store, issuers=[ISS])
    with pytest.raises(TypeError):
        Bootstrap(mapping, idp=ISS, group=BOOT)  # type: ignore[call-arg]


@pytest.mark.parametrize("audit", [None, "log", 5])
def test_audit_must_be_callable(audit: object) -> None:
    store = MemoryStore()
    mapping = RoleMapping(store, issuers=[ISS])
    with pytest.raises(ValueError, match="audit must be callable"):
        Bootstrap(mapping, idp=ISS, group=BOOT, audit=audit)  # type: ignore[arg-type]


class _Barrier(MemoryStore):
    """Holds every claim's transaction until both have passed ``is_open()``."""

    def __init__(self) -> None:
        super().__init__()
        self.bar = threading.Barrier(2, timeout=5)

    def transact(self, scope, ops):  # type: ignore[no-untyped-def]
        self.bar.wait()
        super().transact(scope, ops)


def test_racing_claims_have_one_winner() -> None:
    env = Env(_Barrier())
    wins: list[str] = []
    errs: list[BaseException] = []

    def go(sub: str) -> None:
        try:
            env.boot.claim(_tok([BOOT], sub=sub))
            wins.append(sub)
        except BaseException as exc:
            errs.append(exc)

    threads = [threading.Thread(target=go, args=(s,)) for s in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(wins) == 1
    assert len(errs) == 1
    assert type(errs[0]) is BootstrapRefusedError  # not a raw ConditionFailedError
    assert not isinstance(errs[0], ConditionFailedError)
    assert len(env.audit) == 1
    assert _marker(env)["by"] == f"{ISS}|{wins[0]}"  # type: ignore[index]


class _Unknown(MemoryStore):
    """The transaction raises an unknown outcome, applied or not."""

    def __init__(self, *, applied: bool) -> None:
        super().__init__()
        self.applied = applied

    def transact(self, scope, ops):  # type: ignore[no-untyped-def]
        if self.applied:
            super().transact(scope, ops)
        raise TransactionOutcomeUnknownError("answer lost")


def test_unknown_outcome_that_committed_finishes_as_success() -> None:
    env = Env(_Unknown(applied=True))
    who = env.boot.claim(_tok([BOOT]))
    assert who.is_org_admin
    assert env.mapping.mapping(ISS, BOOT) == (None, ORG_ADMIN)
    assert _marker(env) is not None
    assert [e["event"] for e in env.audit] == ["bootstrap.claimed"]


def test_unknown_outcome_that_did_not_commit_is_retryable_and_still_open() -> None:
    env = Env(_Unknown(applied=False))
    with pytest.raises(BootstrapRetryError):
        env.boot.claim(_tok([BOOT]))
    assert env.boot.is_open()
    assert _marker(env) is None
    assert env.mapping.mapping(ISS, BOOT) is None
    assert env.audit == []


class _OtherWins(MemoryStore):
    """Another claimant's transaction commits instead of ours, and the answer is lost."""

    def transact(self, scope, ops):  # type: ignore[no-untyped-def]
        first = ops[0]
        other = Put(
            first.key, {**first.data, "by": f"{ISS}|winner", "at": NOW + 5}, when=first.when
        )
        super().transact(scope, [other, ops[1]])
        raise TransactionOutcomeUnknownError("answer lost")


def test_unknown_outcome_after_someone_else_won_is_refused() -> None:
    env = Env(_OtherWins())
    with pytest.raises(BootstrapRefusedError, match="someone else"):
        env.boot.claim(_tok([BOOT], sub="loser"))
    assert env.audit == []
    assert _marker(env)["by"] == f"{ISS}|winner"  # type: ignore[index]


class _SameClaimantEarlier(MemoryStore):
    """The same claimant's earlier request commits first (at a later time), answer lost."""

    def transact(self, scope, ops):  # type: ignore[no-untyped-def]
        first = ops[0]
        super().transact(
            scope, [Put(first.key, {**first.data, "at": NOW + 5}, when=first.when), ops[1]]
        )
        raise TransactionOutcomeUnknownError("answer lost")


def test_audit_event_comes_from_the_stored_marker() -> None:
    env = Env(_SameClaimantEarlier())
    env.boot.claim(_tok([BOOT]))
    assert _marker(env)["at"] == NOW + 5  # type: ignore[index]
    assert env.audit == [{"event": "bootstrap.claimed", **_marker(env)}]  # type: ignore[dict-item]


class _ReadFailsAfterCommit(MemoryStore):
    """The transaction commits, the answer is lost, and the first re-read fails."""

    fail_get = False

    def transact(self, scope, ops):  # type: ignore[no-untyped-def]
        super().transact(scope, ops)
        self.fail_get = True
        raise TransactionOutcomeUnknownError("answer lost")

    def get(self, scope, key):  # type: ignore[no-untyped-def]
        if self.fail_get:
            self.fail_get = False
            raise TransactionConflictError("read failed")
        return super().get(scope, key)


def test_failed_reread_is_retryable_and_the_retry_succeeds_and_notifies() -> None:
    env = Env(_ReadFailsAfterCommit())
    with pytest.raises(BootstrapRetryError):
        env.boot.claim(_tok([BOOT]))
    assert env.audit == []
    who = env.boot.claim(_tok([BOOT]))  # the recorded claimant is already org_admin
    assert who.is_org_admin
    assert [e["event"] for e in env.audit] == ["bootstrap.claimed"]
    assert env.audit[0] == {"event": "bootstrap.claimed", **_marker(env)}  # type: ignore[dict-item]


def test_idempotent_for_the_recorded_claimant_but_not_for_others(env: Env) -> None:
    env.boot.claim(_tok([BOOT]))
    assert env.boot.claim(_tok([BOOT])).is_org_admin
    assert len(env.audit) == 2
    with pytest.raises(BootstrapRefusedError, match="someone else"):
        env.boot.claim(_tok([BOOT], sub="u-9"))


def test_marker_for_this_claimant_with_mapping_gone_is_refused_and_says_why(env: Env) -> None:
    env.boot.claim(_tok([BOOT]))
    env.mapping.remove_mapping(ORG, idp=ISS, group=BOOT, team=None)
    with pytest.raises(BootstrapRefusedError, match="mapping has since been removed"):
        env.boot.claim(_tok([BOOT]))
    assert env.mapping.mapping(ISS, BOOT) is None
    assert len(env.audit) == 1


class _Interleave(MemoryStore):
    """Runs ``hook`` once, just before the first transaction."""

    hook: Callable[[], None] | None = None

    def transact(self, scope, ops):  # type: ignore[no-untyped-def]
        hook, self.hook = self.hook, None
        if hook:
            hook()
        super().transact(scope, ops)


def test_marker_absent_condition_holds_when_the_mapping_was_removed_meanwhile() -> None:
    """A passes is_open(); B claims; an admin removes the mapping; A's transaction must lose."""
    store = _Interleave()
    env = Env(store)

    def interleave() -> None:
        env.boot.claim(_tok([BOOT], sub="B"))
        env.mapping.remove_mapping(ORG, idp=ISS, group=BOOT, team=None)

    store.hook = interleave
    with pytest.raises(BootstrapRefusedError):
        env.boot.claim(_tok([BOOT], sub="A"))
    assert _marker(env)["by"] == f"{ISS}|B"  # type: ignore[index]
    assert env.mapping.mapping(ISS, BOOT) is None
    assert len(env.audit) == 1


def test_stored_marker_group_is_the_bootstrap_group_among_many(env: Env) -> None:
    env.boot.claim(_tok(["grp-a", BOOT, "grp-z"]))
    assert _marker(env)["group"] == BOOT  # type: ignore[index]
    assert env.mapping.mapping(ISS, "grp-a") is None
    assert env.mapping.mapping(ISS, "grp-z") is None


@pytest.mark.parametrize("group", ["", " " + BOOT, BOOT + " ", "a\x00b", "x" * 500])
def test_misconfigured_group_is_refused(group: str) -> None:
    store = MemoryStore()
    with pytest.raises(ValueError, match="bad bootstrap configuration"):
        Bootstrap(RoleMapping(store, issuers=[ISS]), idp=ISS, group=group, audit=lambda e: None)


def test_misconfigured_idp_is_refused() -> None:
    store = MemoryStore()
    with pytest.raises(ValueError, match="bad bootstrap configuration"):
        Bootstrap(
            RoleMapping(store, issuers=[ISS]),
            idp="https://nope.example.test",
            group=BOOT,
            audit=lambda e: None,
        )


_MAPPING = "sto.identity.mapping"


def _violations(src: str, module: str = "sto.identity.bootstrap") -> list[str]:
    """Uses of a private name of ``mapping.py`` (or of private state of the mapping)."""
    import ast

    tree = ast.parse(src)
    pkg = module.rsplit(".", 1)[0]
    bound: set[str] = set()  # local names bound to the mapping module
    found: list[str] = []

    def resolve(node: ast.ImportFrom) -> str:
        if not node.level:
            return node.module or ""
        base = pkg.split(".")[: len(pkg.split(".")) - (node.level - 1)]
        return ".".join([*base, *([node.module] if node.module else [])])

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            target = resolve(node)
            for alias in node.names:
                if target == _MAPPING and alias.name.startswith("_"):
                    found.append(f"import {alias.name}")
                if f"{target}.{alias.name}" == _MAPPING:
                    bound.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == _MAPPING:
                    bound.add(alias.asname or alias.name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            val = node.value
            dotted = ast.unparse(val)
            if dotted in bound or dotted == _MAPPING:
                found.append(f"{dotted}.{node.attr}")
            if isinstance(val, ast.Attribute) and val.attr in ("_mapping", "mapping"):
                found.append(f"{dotted}.{node.attr}")
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "getattr":
            found.append("getattr")
    return found


_BYPASSES = {
    "relative import": "from .mapping import _check_text\n",
    "from package": "from sto.identity import mapping\nmapping._too_long('x')\n",
    "module alias": "import sto.identity.mapping as m\nm._disabled_key('a', 'b')\n",
    "plain module import": "import sto.identity.mapping\nsto.identity.mapping._MAP\n",
    "getattr": "import sto.identity.mapping as m\ngetattr(m, '_check_' + 'text')\n",
    "instance privates": "def f(self):\n    return self._mapping._store, self._mapping._issuers\n",
}


@pytest.mark.parametrize("name", list(_BYPASSES))
def test_bootstrap_guard_catches_each_bypass(name: str) -> None:
    assert _violations(_BYPASSES[name]), name


def test_bootstrap_guard_allows_public_names() -> None:
    ok = "from .mapping import check_text\nfrom sto.identity import mapping\nmapping.map_key\n"
    assert _violations(ok) == []


def test_bootstrap_imports_no_private_name_from_mapping() -> None:
    import pathlib

    import sto.identity.bootstrap as mod

    text = pathlib.Path(mod.__file__).read_text()
    assert _violations(text) == []
    assert "MAP#" not in text.split('"""', 2)[2]  # best effort: no copied key layout


def test_bootstrap_uses_the_mappings_store_only() -> None:
    import inspect

    assert "store" not in inspect.signature(Bootstrap).parameters
    env = Env()
    assert env.boot._store is env.mapping.store
