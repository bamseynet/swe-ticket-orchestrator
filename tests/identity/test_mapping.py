"""Group mapping and roles (D3-02): data-driven, resolved on every request, fail closed."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from sto.config.org_policy import ORG_ADMIN, PermissionDeniedError, Principal
from sto.domain.errors import PermanentError
from sto.identity.fake_issuer import FakeIssuer
from sto.identity.mapping import (
    BUILTIN_ROLES,
    MAX_NAME_BYTES,
    InvalidMappingError,
    NoAccessError,
    RoleMapping,
    ServiceIdentity,
    UserDisabledError,
    UserIdentity,
)
from sto.identity.oidc import OidcConfig, OidcValidator, StaticJwks, VerifiedToken
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, ConditionFailedError, Key, TeamScope

ISS = "https://idp.example.test"
OTHER = "https://other.example.test"
CLIENT = "sto-client"
NOW = 1_800_000_000.0
ORG = Principal("root", frozenset({ORG_ADMIN}))
ADMIN_A = Principal("ann", frozenset({"team_admin"}), team="alpha")


@pytest.fixture(scope="module")
def issuer() -> FakeIssuer:
    return FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)


@pytest.fixture(scope="module")
def validator(issuer: FakeIssuer) -> OidcValidator:
    cfg = OidcConfig(issuer=ISS, audience=CLIENT, audience_claim="client_id", token_use="access")
    return OidcValidator(cfg, StaticJwks(issuer.jwks()), clock=lambda: NOW)


@pytest.fixture
def mapping() -> RoleMapping:
    return RoleMapping(MemoryStore(), issuers=[ISS, OTHER], clock=lambda: NOW)


def _user(issuer: FakeIssuer, validator: OidcValidator, groups: list[str], sub: str = "u-1"):  # type: ignore[no-untyped-def]
    token = issuer.issue(
        sub=sub, audience=CLIENT, groups=groups,
        extra={"client_id": CLIENT, "token_use": "access"},
    )  # fmt: skip
    return validator.validate(token)


def _m2m(issuer: FakeIssuer, validator: OidcValidator, **extra: object):  # type: ignore[no-untyped-def]
    token = issuer.issue(
        sub=CLIENT, audience=CLIENT, extra={"client_id": CLIENT, "token_use": "access", **extra}
    )
    return validator.validate(token)


def test_mapped_group_gives_team_role(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    who = mapping.resolve(_user(issuer, validator, ["g-1"]))
    assert isinstance(who, UserIdentity)
    assert who.roles_in("alpha") == frozenset({"reviewer"})
    assert who.principal("alpha").roles == frozenset({"reviewer"})
    assert who.principal("alpha").team == "alpha"


def test_roles_from_several_groups_union(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-2", team="alpha", role="qa")
    who = mapping.resolve(_user(issuer, validator, ["g-1", "g-2", "other"]))
    assert isinstance(who, UserIdentity)
    assert who.roles_in("alpha") == {"reviewer", "qa"}
    assert who.roles_in("beta") == frozenset()


def test_changed_mapping_applies_on_next_request(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    token = _user(issuer, validator, ["g-1"])
    first = mapping.resolve(token)
    assert isinstance(first, UserIdentity)
    assert first.roles_in("alpha") == {"reviewer"}
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="qa")
    second = mapping.resolve(token)  # same token, no new sign-in
    assert isinstance(second, UserIdentity)
    assert second.roles_in("alpha") == {"qa"}
    mapping.remove_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha")
    with pytest.raises(NoAccessError):
        mapping.resolve(token)


def test_unmapped_user_has_no_access(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    with pytest.raises(NoAccessError):
        mapping.resolve(_user(issuer, validator, ["not-mapped"]))
    with pytest.raises(NoAccessError):
        mapping.resolve(_user(issuer, validator, []))


def test_mapping_is_per_idp(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=OTHER, group="g-1", team="alpha",
                        role="reviewer")  # fmt: skip
    with pytest.raises(NoAccessError):
        mapping.resolve(_user(issuer, validator, ["g-1"]))


def test_group_ids_are_exact(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="Admins", team="alpha", role="reviewer")
    for spoof in ("admins", "Admins ", "Admins#x", "ADMINS"):
        with pytest.raises(NoAccessError):
            mapping.resolve(_user(issuer, validator, [spoof]))


def test_disabled_user_refused_immediately(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    token = _user(issuer, validator, ["g-1"])
    mapping.resolve(token)
    mapping.disable_user(ORG, idp=ISS, subject="u-1")
    with pytest.raises(UserDisabledError):
        mapping.resolve(token)  # the very next request, same unexpired token
    mapping.enable_user(ORG, idp=ISS, subject="u-1")
    mapping.resolve(token)


def test_disabled_wins_over_unmapped(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.disable_user(ORG, idp=ISS, subject="u-1")
    with pytest.raises(UserDisabledError):
        mapping.resolve(_user(issuer, validator, []))


def test_disabling_is_per_subject_and_idp(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    mapping.disable_user(ORG, idp=OTHER, subject="u-1")
    mapping.disable_user(ORG, idp=ISS, subject="u-2")
    mapping.resolve(_user(issuer, validator, ["g-1"]))


def test_only_admins_disable(mapping) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(PermissionDeniedError):
        mapping.disable_user(ADMIN_A, idp=ISS, subject="u-1")


# --- custom roles ---------------------------------------------------------------------------


def test_custom_role_declared_per_team_and_mapped(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.declare_roles(ADMIN_A, team="alpha", roles=["security_officer", "change_manager"])
    mapping.set_mapping(ADMIN_A, idp=ISS, group="sec", team="alpha", role="security_officer")
    who = mapping.resolve(_user(issuer, validator, ["sec"]))
    assert isinstance(who, UserIdentity)
    assert who.roles_in("alpha") == {"security_officer"}
    assert mapping.roles("alpha") == frozenset(BUILTIN_ROLES) | {
        "security_officer",
        "change_manager",
    }
    assert mapping.roles("beta") == frozenset(BUILTIN_ROLES)


def test_custom_role_of_one_team_is_not_mappable_in_another(mapping) -> None:  # type: ignore[no-untyped-def]
    mapping.declare_roles(ADMIN_A, team="alpha", roles=["security_officer"])
    admin_b = Principal("bob", frozenset({"team_admin"}), team="beta")
    with pytest.raises(InvalidMappingError):
        mapping.set_mapping(admin_b, idp=ISS, group="sec", team="beta", role="security_officer")


def test_undeclared_role_refused(mapping) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(InvalidMappingError):
        mapping.set_mapping(ADMIN_A, idp=ISS, group="g", team="alpha", role="nonesuch")


def test_undeclaring_a_role_stops_it_applying(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.declare_roles(ADMIN_A, team="alpha", roles=["security_officer"])
    mapping.set_mapping(ADMIN_A, idp=ISS, group="sec", team="alpha", role="security_officer")
    mapping.set_mapping(ADMIN_A, idp=ISS, group="rev", team="alpha", role="reviewer")
    mapping.declare_roles(ADMIN_A, team="alpha", roles=[])
    token = _user(issuer, validator, ["sec", "rev"])
    who = mapping.resolve(token)
    assert isinstance(who, UserIdentity)
    assert who.roles_in("alpha") == {"reviewer"}


@pytest.mark.parametrize("role", [ORG_ADMIN, *BUILTIN_ROLES, "Bad Role", "", "x#y"])
def test_declaring_reserved_or_malformed_roles_refused(mapping, role) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(InvalidMappingError):
        mapping.declare_roles(ADMIN_A, team="alpha", roles=[role])


# --- org_admin ------------------------------------------------------------------------------


def test_mapping_a_team_group_to_org_admin_is_refused(mapping) -> None:  # type: ignore[no-untyped-def]
    for who in (ADMIN_A, ORG):
        with pytest.raises(InvalidMappingError):
            mapping.set_mapping(who, idp=ISS, group="g", team="alpha", role=ORG_ADMIN)
    with pytest.raises(InvalidMappingError):  # and it cannot be smuggled in as a custom role
        mapping.declare_roles(ORG, team="alpha", roles=[ORG_ADMIN])


def test_org_level_mapping_needs_org_admin_and_only_org_admin_role(  # type: ignore[no-untyped-def]
    mapping, issuer, validator
) -> None:
    with pytest.raises(PermissionDeniedError):
        mapping.set_mapping(ADMIN_A, idp=ISS, group="boss", team=None, role=ORG_ADMIN)
    with pytest.raises(InvalidMappingError):
        mapping.set_mapping(ORG, idp=ISS, group="boss", team=None, role="reviewer")
    mapping.set_mapping(ORG, idp=ISS, group="boss", team=None, role=ORG_ADMIN)
    who = mapping.resolve(_user(issuer, validator, ["boss"]))
    assert isinstance(who, UserIdentity)
    assert who.principal(None).is_org_admin
    assert who.roles_in("alpha") == frozenset()  # org_admin is not a team role


def _raw_roles(store: MemoryStore, team: str, roles: list[str]) -> None:
    store.put(TeamScope(team), Key("TEAM", "ROLES"), {"roles": roles})


def _raw_map(store: MemoryStore, group: str, team: str | None, role: str, idp: str = ISS) -> None:
    store.put(PLATFORM, Key("ORG", f"MAP#{idp}#{group}"), {"team": team, "role": role})


def test_stored_team_org_admin_is_ignored_on_read(issuer, validator) -> None:  # type: ignore[no-untyped-def]
    """M5: a hand-written item, with org_admin even declared as a team role, grants nothing,
    so only the org_admin check on read stops it."""
    store = MemoryStore()
    m = RoleMapping(store, issuers=[ISS])
    _raw_roles(store, "alpha", [ORG_ADMIN])
    _raw_map(store, "g", "alpha", ORG_ADMIN)
    with pytest.raises(NoAccessError):
        m.resolve(_user(issuer, validator, ["g"]))


def test_stored_org_level_non_admin_record_grants_nothing(issuer, validator) -> None:  # type: ignore[no-untyped-def]
    """M6: an org-level record can only carry org_admin."""
    store = MemoryStore()
    m = RoleMapping(store, issuers=[ISS])
    _raw_map(store, "g", None, "reviewer")
    with pytest.raises(NoAccessError):
        m.resolve(_user(issuer, validator, ["g"]))


def test_write_side_org_admin_refusal_does_not_rest_on_declared_roles() -> None:
    """M7: even when org_admin sits in a team's declared roles, mapping it is refused."""
    store = MemoryStore()
    m = RoleMapping(store, issuers=[ISS])
    _raw_roles(store, "alpha", [ORG_ADMIN])
    with pytest.raises(InvalidMappingError, match="org_admin"):
        m.set_mapping(ORG, idp=ISS, group="g", team="alpha", role=ORG_ADMIN)
    assert m.mapping(ISS, "g") is None


def test_principal_for_a_team_excludes_org_level_roles(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    """M21: the org-level role never leaks into a team principal, nor team roles into the org's."""
    mapping.set_mapping(ORG, idp=ISS, group="boss", team=None, role=ORG_ADMIN)
    mapping.set_mapping(ORG, idp=ISS, group="rev", team="alpha", role="reviewer")
    who = mapping.resolve(_user(issuer, validator, ["boss", "rev"]))
    assert isinstance(who, UserIdentity)
    assert who.principal("alpha").roles == {"reviewer"}
    assert not who.principal("alpha").is_org_admin
    assert who.principal(None).roles == {ORG_ADMIN}
    assert who.principal("beta").roles == frozenset()


def test_second_issuer_resolves_separately() -> None:
    """M20b: a token is looked up under its own issuer, and an unconfigured one is refused."""
    second = "https://second.example.test"
    iss_a = FakeIssuer(issuer=ISS, key_id="a", clock=lambda: NOW)
    iss_b = FakeIssuer(issuer=second, key_id="b", clock=lambda: NOW)

    def check(fake: FakeIssuer, issuer_url: str) -> VerifiedToken:
        cfg = OidcConfig(issuer=issuer_url, audience=CLIENT)
        v = OidcValidator(cfg, StaticJwks(fake.jwks()), clock=lambda: NOW)
        return v.validate(fake.issue(sub="u", audience=CLIENT, groups=["g"]))

    tok_a, tok_b = check(iss_a, ISS), check(iss_b, second)
    m = RoleMapping(MemoryStore(), issuers=[ISS, second])
    m.set_mapping(ORG, idp=second, group="g", team="beta", role="qa")
    with pytest.raises(NoAccessError):  # same group id under the other issuer is not mapped
        m.resolve(tok_a)
    who = m.resolve(tok_b)
    assert isinstance(who, UserIdentity)
    assert who.roles_in("beta") == {"qa"}
    m.disable_user(ORG, idp=ISS, subject="u")
    with pytest.raises(UserDisabledError):
        m.resolve(tok_a)
    assert isinstance(m.resolve(tok_b), UserIdentity)  # same sub, other issuer: not disabled
    only_first = RoleMapping(MemoryStore(), issuers=[ISS])
    with pytest.raises(NoAccessError):
        only_first.resolve(tok_b)


def test_enable_user_needs_org_admin(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    """M16: a team admin or anyone else cannot re-enable a disabled user."""
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    mapping.disable_user(ORG, idp=ISS, subject="u-1")
    for who in (ADMIN_A, Principal("dan", frozenset({"developer"}), team="alpha"), Principal("x")):
        with pytest.raises(PermissionDeniedError):
            mapping.enable_user(who, idp=ISS, subject="u-1")
    with pytest.raises(UserDisabledError):
        mapping.resolve(_user(issuer, validator, ["g-1"]))


# --- idp must be a configured issuer (disable and mapping must not fail open) -----------------


@pytest.mark.parametrize("idp", [ISS + "/", "not a url", "", ISS.upper(), ISS + "#", 5])
def test_unconfigured_idp_refused_everywhere(mapping, idp) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(InvalidMappingError):
        mapping.disable_user(ORG, idp=idp, subject="u-1")
    with pytest.raises(InvalidMappingError):
        mapping.enable_user(ORG, idp=idp, subject="u-1")
    with pytest.raises(InvalidMappingError):
        mapping.set_mapping(ORG, idp=idp, group="g", team="alpha", role="reviewer")
    with pytest.raises(InvalidMappingError):
        mapping.remove_mapping(ORG, idp=idp, group="g", team="alpha")


def test_disable_with_the_right_idp_does_take_effect(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    with pytest.raises(InvalidMappingError):
        mapping.disable_user(ORG, idp=ISS + "/", subject="u-1")
    mapping.resolve(_user(issuer, validator, ["g-1"]))  # still resolvable: nothing was written
    mapping.disable_user(ORG, idp=ISS, subject="u-1")
    with pytest.raises(UserDisabledError):
        mapping.resolve(_user(issuer, validator, ["g-1"]))


def test_needs_at_least_one_valid_issuer() -> None:
    for bad in ([], [""], ["a#b"], ["x" * 500]):
        with pytest.raises(ValueError, match="issuer"):
            RoleMapping(MemoryStore(), issuers=bad)


# --- races between the check and the write -----------------------------------------------------


class _Racing(MemoryStore):
    """After the first read of a MAP item, run ``hook`` once: a competing write in the gap."""

    def __init__(self) -> None:
        super().__init__()
        self.hook: Callable[[], None] | None = None

    def get(self, scope, key):  # type: ignore[no-untyped-def]
        item = super().get(scope, key)
        if self.hook is not None and key.sk.startswith("MAP#"):
            hook, self.hook = self.hook, None
            hook()
        return item


ADMIN_B = Principal("bob", frozenset({"team_admin"}), team="beta")


def test_racing_new_mapping_cannot_overwrite(mapping) -> None:  # type: ignore[no-untyped-def]
    """Team B read 'absent'; team A's write lands first; B's write must fail, not overwrite."""
    store = _Racing()
    m = RoleMapping(store, issuers=[ISS])
    store.hook = lambda: m.set_mapping(ADMIN_A, idp=ISS, group="g", team="alpha", role="reviewer")
    with pytest.raises(ConditionFailedError):
        m.set_mapping(ADMIN_B, idp=ISS, group="g", team="beta", role="qa")
    assert m.mapping(ISS, "g") == ("alpha", "reviewer")


def test_racing_change_cannot_overwrite() -> None:
    """B's admin legitimately holds the group; org moves it to A between B's read and write."""
    store = _Racing()
    m = RoleMapping(store, issuers=[ISS])
    m.set_mapping(ADMIN_B, idp=ISS, group="g", team="beta", role="qa")
    store.hook = lambda: m.set_mapping(ORG, idp=ISS, group="g", team="alpha", role="reviewer")
    with pytest.raises(ConditionFailedError):
        m.set_mapping(ADMIN_B, idp=ISS, group="g", team="beta", role="reviewer")
    assert m.mapping(ISS, "g") == ("alpha", "reviewer")


def test_racing_remove_cannot_delete_a_moved_mapping() -> None:
    store = _Racing()
    m = RoleMapping(store, issuers=[ISS])
    m.set_mapping(ADMIN_B, idp=ISS, group="g", team="beta", role="qa")
    store.hook = lambda: m.set_mapping(ORG, idp=ISS, group="g", team="alpha", role="reviewer")
    with pytest.raises(ConditionFailedError):
        m.remove_mapping(ADMIN_B, idp=ISS, group="g", team="beta")
    assert m.mapping(ISS, "g") == ("alpha", "reviewer")


def test_remove_mapping_team_must_match_stored_team(mapping) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ORG, idp=ISS, group="g", team="alpha", role="reviewer")
    with pytest.raises(InvalidMappingError):
        mapping.remove_mapping(ORG, idp=ISS, group="g", team="beta")
    with pytest.raises(InvalidMappingError):
        mapping.remove_mapping(ORG, idp=ISS, group="g", team=None)
    assert mapping.mapping(ISS, "g") == ("alpha", "reviewer")
    mapping.remove_mapping(ORG, idp=ISS, group="g", team="alpha")
    assert mapping.mapping(ISS, "g") is None
    mapping.remove_mapping(ORG, idp=ISS, group="g", team="alpha")  # already gone: no error


# --- long names ---------------------------------------------------------------------------------


def test_overlong_group_in_token_is_skipped_not_a_lockout(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    for long_group in ("g" * 1200, "é" * 300, "g" * (MAX_NAME_BYTES + 1)):
        who = mapping.resolve(_user(issuer, validator, [long_group, "g-1"]))
        assert isinstance(who, UserIdentity)
        assert who.roles_in("alpha") == {"reviewer"}
    with pytest.raises(NoAccessError):  # a too-long group alone is just unmapped
        mapping.resolve(_user(issuer, validator, ["g" * 1200]))


def test_group_at_the_limit_still_works(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    group = "g" * MAX_NAME_BYTES
    mapping.set_mapping(ADMIN_A, idp=ISS, group=group, team="alpha", role="reviewer")
    assert isinstance(mapping.resolve(_user(issuer, validator, [group])), UserIdentity)
    mapping.disable_user(ORG, idp=ISS, subject="s" * MAX_NAME_BYTES)


def test_overlong_subject_is_a_domain_refusal(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    with pytest.raises(NoAccessError):
        mapping.resolve(_user(issuer, validator, ["g-1"], sub="s" * 2000))


def test_overlong_names_on_write_are_domain_refusals(mapping) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(InvalidMappingError):
        mapping.set_mapping(ORG, idp=ISS, group="g" * 2000, team="alpha", role="reviewer")
    with pytest.raises(InvalidMappingError):
        mapping.disable_user(ORG, idp=ISS, subject="s" * 2000)
    with pytest.raises(InvalidMappingError):
        mapping.remove_mapping(ORG, idp=ISS, group="g" * 2000, team="alpha")
    with pytest.raises(InvalidMappingError):
        mapping.set_mapping(ORG, idp=ISS, group="g", team="t" * 2000, role="reviewer")


def test_records_store_who_and_when(mapping) -> None:  # type: ignore[no-untyped-def]
    store = MemoryStore()
    m = RoleMapping(store, issuers=[ISS], clock=lambda: 1234.5)
    m.set_mapping(ADMIN_A, idp=ISS, group="g", team="alpha", role="reviewer")
    m.disable_user(ORG, idp=ISS, subject="u")
    for sk in (f"MAP#{ISS}#g", f"DISABLED#{ISS}#u"):
        item = store.get(PLATFORM, Key("ORG", sk))
        assert item is not None
        assert item.data["at"] == 1234.5
        assert item.data["by"] in ("ann", "root")


# --- who may write --------------------------------------------------------------------------


def test_team_admin_only_for_own_team(mapping) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(PermissionDeniedError):
        mapping.set_mapping(ADMIN_A, idp=ISS, group="g", team="beta", role="reviewer")
    with pytest.raises(PermissionDeniedError):
        mapping.declare_roles(ADMIN_A, team="beta", roles=["x"])
    with pytest.raises(PermissionDeniedError):
        mapping.remove_mapping(ADMIN_A, idp=ISS, group="g", team="beta")
    dev = Principal("dan", frozenset({"developer"}), team="alpha")
    with pytest.raises(PermissionDeniedError):
        mapping.set_mapping(dev, idp=ISS, group="g", team="alpha", role="reviewer")
    # a team_admin role held outside any team (team=None) is not a team admin
    loose = Principal("lou", frozenset({"team_admin"}))
    with pytest.raises(PermissionDeniedError):
        mapping.set_mapping(loose, idp=ISS, group="g", team="alpha", role="reviewer")
    mapping.set_mapping(ORG, idp=ISS, group="g", team="beta", role="reviewer")


def test_mapping_cannot_be_hijacked_across_teams(mapping) -> None:  # type: ignore[no-untyped-def]
    """A group maps to one (team, role). Team B's admin cannot take over team A's group."""
    admin_b = Principal("bob", frozenset({"team_admin"}), team="beta")
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g", team="alpha", role="reviewer")
    with pytest.raises(PermissionDeniedError):
        mapping.set_mapping(admin_b, idp=ISS, group="g", team="beta", role="reviewer")
    with pytest.raises(PermissionDeniedError):
        mapping.remove_mapping(admin_b, idp=ISS, group="g", team="beta")
    assert mapping.mapping(ISS, "g") == ("alpha", "reviewer")


@pytest.mark.parametrize(
    "kw",
    [
        {"idp": "", "group": "g"},
        {"idp": "a#b", "group": "g"},
        {"idp": ISS, "group": ""},
        {"idp": ISS, "group": " g"},
        {"idp": ISS, "group": "g\n"},
    ],
)
def test_malformed_idp_or_group_refused(mapping, kw) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(InvalidMappingError):
        mapping.set_mapping(ADMIN_A, team="alpha", role="reviewer", **kw)


def test_bad_team_refused(mapping) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(InvalidMappingError):
        mapping.set_mapping(ORG, idp=ISS, group="g", team="a#b", role="reviewer")


def test_errors_are_permanent() -> None:
    for err in (InvalidMappingError, NoAccessError, UserDisabledError):
        assert issubclass(err, PermanentError)


# --- service identities (PLAN 9.2, sso.md) --------------------------------------------------


def test_m2m_token_validates_with_empty_groups_and_is_a_service(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    token = _m2m(issuer, validator)
    assert token.subject == CLIENT
    assert token.groups == ()
    who = mapping.resolve(token)
    assert isinstance(who, ServiceIdentity)
    assert not isinstance(who, UserIdentity)
    assert who.client_id == CLIENT
    assert who.eligible_for_gate is False


def test_service_never_a_user_even_with_groups_and_mappings(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    token = _m2m(issuer, validator, **{"groups": ["g-1"]})
    assert token.groups == ("g-1",)
    who = mapping.resolve(token)
    assert isinstance(who, ServiceIdentity)
    assert not hasattr(who, "roles_in")


def test_service_rule_is_explicit_sub_equals_client_id(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.set_mapping(ADMIN_A, idp=ISS, group="g-1", team="alpha", role="reviewer")
    user = mapping.resolve(_user(issuer, validator, ["g-1"], sub="someone"))
    assert isinstance(user, UserIdentity)
    assert user.eligible_for_gate is True
    # a user token whose sub differs from client_id by case or whitespace is a user
    for sub in ("STO-CLIENT", f"{CLIENT} "):
        with pytest.raises(NoAccessError):
            mapping.resolve(_user(issuer, validator, [], sub=sub))


def test_token_without_client_id_is_not_a_service(mapping, issuer) -> None:  # type: ignore[no-untyped-def]
    cfg = OidcConfig(issuer=ISS, audience=CLIENT)
    v = OidcValidator(cfg, StaticJwks(issuer.jwks()), clock=lambda: NOW)
    token = v.validate(issuer.issue(sub=CLIENT, audience=CLIENT))
    with pytest.raises(NoAccessError):  # no client_id claim: a user named like the client
        mapping.resolve(token)


def test_non_string_client_id_is_not_a_service(mapping, issuer) -> None:  # type: ignore[no-untyped-def]
    cfg = OidcConfig(issuer=ISS, audience=CLIENT)
    v = OidcValidator(cfg, StaticJwks(issuer.jwks()), clock=lambda: NOW)
    for client_id in (1, ["1"], None):
        token = v.validate(issuer.issue(sub="1", audience=CLIENT, extra={"client_id": client_id}))
        assert token.claims["client_id"] == (tuple(client_id) if client_id == ["1"] else client_id)
        with pytest.raises(NoAccessError):
            mapping.resolve(token)


def test_disabled_service_is_refused(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.disable_user(ORG, idp=ISS, subject=CLIENT)
    with pytest.raises(UserDisabledError):
        mapping.resolve(_m2m(issuer, validator))


def test_service_identity_has_no_principal() -> None:
    assert not hasattr(ServiceIdentity(subject="c", issuer=ISS, client_id="c"), "principal")


def test_token_from_unconfigured_issuer_is_refused_even_as_a_service(issuer, validator) -> None:  # type: ignore[no-untyped-def]
    m = RoleMapping(MemoryStore(), issuers=["https://elsewhere.example.test"])
    with pytest.raises(NoAccessError, match="not configured"):
        m.resolve(_m2m(issuer, validator))
