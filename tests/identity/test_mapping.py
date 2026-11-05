"""Group mapping and roles (D3-02): data-driven, resolved on every request, fail closed."""

from __future__ import annotations

import pytest

from sto.config.org_policy import ORG_ADMIN, PermissionDeniedError, Principal
from sto.domain.errors import PermanentError
from sto.identity.fake_issuer import FakeIssuer
from sto.identity.mapping import (
    BUILTIN_ROLES,
    InvalidMappingError,
    NoAccessError,
    RoleMapping,
    ServiceIdentity,
    UserDisabledError,
    UserIdentity,
)
from sto.identity.oidc import OidcConfig, OidcValidator, StaticJwks
from sto.store.memory import MemoryStore

ISS = "https://idp.example.test"
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
    return RoleMapping(MemoryStore())


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
    mapping.set_mapping(ADMIN_A, idp="https://other.example.test", group="g-1", team="alpha",
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
    mapping.disable_user(ORG, idp="https://other.example.test", subject="u-1")
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


def test_stored_team_org_admin_is_ignored_on_read(issuer, validator) -> None:  # type: ignore[no-untyped-def]
    """Defence in depth: a hand-written store item cannot make a team org_admin."""
    from sto.store.ports import PLATFORM, Key

    store = MemoryStore()
    m = RoleMapping(store)
    m.set_mapping(ADMIN_A, idp=ISS, group="g", team="alpha", role="reviewer")
    item = next(iter(store.query(PLATFORM, "ORG", sk_prefix="MAP#").items))
    store.put(PLATFORM, Key(item.key.pk, item.key.sk), {"team": "alpha", "role": ORG_ADMIN})
    with pytest.raises(NoAccessError):
        m.resolve(_user(issuer, validator, ["g"]))


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


def test_non_string_client_id_is_not_a_service(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    token = issuer.issue(
        sub="1", audience=CLIENT, extra={"client_id": CLIENT, "token_use": "access"}
    )
    cfg = OidcConfig(issuer=ISS, audience=CLIENT, audience_claim="client_id", token_use="access")
    v = OidcValidator(cfg, StaticJwks(issuer.jwks()), clock=lambda: NOW)
    assert v.validate(token).subject == "1"
    with pytest.raises(NoAccessError):
        mapping.resolve(v.validate(token))


def test_disabled_service_is_refused(mapping, issuer, validator) -> None:  # type: ignore[no-untyped-def]
    mapping.disable_user(ORG, idp=ISS, subject=CLIENT)
    with pytest.raises(UserDisabledError):
        mapping.resolve(_m2m(issuer, validator))


def test_service_identity_has_no_principal() -> None:
    assert not hasattr(ServiceIdentity(subject="c", issuer=ISS, client_id="c"), "principal")
