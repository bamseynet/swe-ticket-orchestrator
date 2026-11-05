"""Group mapping and roles (PLAN 9.2 and 9.3, D3-02).

A mapping is data: ``(idp, group ID) -> (team, role)``, one item per group in the platform
partition. Roles are resolved from the store on **every** request (:meth:`RoleMapping.resolve`),
never cached in a token or session, so a changed mapping applies on the next request. Reads are
strongly consistent (the Store port says so). Group IDs match exactly: no case folding, no
trimming, so a lookalike display name does not match.

Roles. The built-ins are ``developer``, ``reviewer``, ``qa``, ``team_admin`` and ``auditor``.
A team declares its own gate roles (``security_officer``, ``change_manager``...) with
:meth:`RoleMapping.declare_roles`; a role is mappable in a team only if built in or declared
there. ``org_admin`` is org-level: a mapping with a team can never carry it (refused on write, and
ignored on read in case an item was written some other way), and an org-level mapping (``team``
is ``None``) can carry nothing else. Declaring a role no longer drops its mappings, but they stop
applying on the next resolve.

Who may write (checked at the :class:`~sto.config.org_policy.Principal` seam): an org admin may
write anything; a team admin only for their own team, and cannot take over or remove a group that
is mapped to another team. Admin self-service rules (an admin who changed a mapping is ineligible
for the affected gate rounds) belong to D3-05 and D3-16, not here.

Disabling. :meth:`RoleMapping.disable_user` writes a record that :meth:`RoleMapping.resolve`
checks first, before groups, so a disabled user is refused on the very next request even with an
unexpired token. It is keyed by ``(idp, subject)``.

Service identities. Rule, stated once: a verified token whose ``sub`` equals its ``client_id``
claim (both non-empty strings, compared exactly) is a **service identity**. That is the shape of a
Cognito ``client_credentials`` (M2M) token, which D3-01 validates with empty groups
(docs/findings/sso.md). :meth:`RoleMapping.resolve` returns a :class:`ServiceIdentity` for it,
whatever groups the token carries and without consulting any mapping, so a service can never
become a user, hold a team role, or be eligible for a gate (``eligible_for_gate`` is ``False`` and
D3-05 must test it). A user token whose ``sub`` happens to equal the client ID is classed a
service: that fails closed. Unverified until D12-10: that a real M2M token has ``sub == client_id``
and that a real user token never does.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sto.config.org_policy import ORG_ADMIN, PermissionDeniedError, Principal
from sto.domain.errors import PermanentError
from sto.identity.oidc import VerifiedToken
from sto.store.ports import PLATFORM, Key, Store, TeamScope

__all__ = [
    "BUILTIN_ROLES",
    "InvalidMappingError",
    "NoAccessError",
    "RoleMapping",
    "ServiceIdentity",
    "UserDisabledError",
    "UserIdentity",
    "is_service_token",
]

BUILTIN_ROLES = ("developer", "reviewer", "qa", "team_admin", "auditor")
TEAM_ADMIN = "team_admin"
_ROLE = re.compile(r"[a-z][a-z0-9_]*", re.ASCII)
_ORG_PK = "ORG"
_MAP = "MAP#"
_DISABLED = "DISABLED#"
_ROLES_KEY = Key("TEAM", "ROLES")


class InvalidMappingError(PermanentError):
    """The mapping, role declaration or name is refused."""


class NoAccessError(PermanentError):
    """The user is verified but nothing maps them to any team: no access."""


class UserDisabledError(PermanentError):
    """The user (or service) is disabled and is refused on every request."""


@dataclass(frozen=True)
class UserIdentity:
    """A human with at least one team or org role, as resolved on this request."""

    subject: str
    issuer: str
    memberships: frozenset[tuple[str | None, str]]  # (team or None for org-level, role)

    eligible_for_gate = True  # a human can be; the gate's own rules decide

    def roles_in(self, team: str) -> frozenset[str]:
        return frozenset(r for t, r in self.memberships if t == team)

    def principal(self, team: str | None) -> Principal:
        """The role seam for ``team`` (``None`` for the org level). Never built from a request."""
        roles = frozenset(r for t, r in self.memberships if t == team)
        return Principal(f"{self.issuer}|{self.subject}", roles, team)


@dataclass(frozen=True)
class ServiceIdentity:
    """A machine client. No roles, no principal, never eligible for a gate."""

    subject: str
    issuer: str
    client_id: str

    eligible_for_gate = False


def is_service_token(token: VerifiedToken) -> bool:
    """The rule: ``sub`` equals the ``client_id`` claim, both non-empty strings."""
    client_id = token.claims.get("client_id")
    return isinstance(client_id, str) and bool(client_id) and token.subject == client_id


def _check_text(label: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidMappingError(f"{label} must be a non-empty string")
    if value != value.strip():
        raise InvalidMappingError(f"{label} must not have surrounding whitespace")
    if any(unicodedata.category(c).startswith("C") for c in value):
        raise InvalidMappingError(f"{label} must not contain control characters")
    return value


def _check_idp(idp: object) -> str:
    text = _check_text("idp", idp)
    if "#" in text:
        raise InvalidMappingError("idp must not contain '#'")
    return text


def _check_team(team: object) -> str:
    try:
        return TeamScope(team).team  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise InvalidMappingError(f"bad team: {exc}") from exc


def _map_key(idp: str, group: str) -> Key:
    return Key(_ORG_PK, f"{_MAP}{idp}#{group}")


def _disabled_key(idp: str, subject: str) -> Key:
    return Key(_ORG_PK, f"{_DISABLED}{idp}#{subject}")


def _may_admin(who: Principal, team: str | None) -> bool:
    if who.is_org_admin:
        return True
    return team is not None and who.team == team and who.has(TEAM_ADMIN)


class RoleMapping:
    def __init__(self, store: Store) -> None:
        self._store = store

    # --- roles ------------------------------------------------------------------------------

    def roles(self, team: str) -> frozenset[str]:
        """Roles mappable in ``team``: the built-ins plus those it declared."""
        item = self._store.get(TeamScope(_check_team(team)), _ROLES_KEY)
        declared = item.data.get("roles", []) if item else []
        return frozenset(BUILTIN_ROLES) | {r for r in declared if isinstance(r, str)}

    def declare_roles(self, who: Principal, *, team: str, roles: Iterable[str]) -> None:
        """Replace the team's custom gate roles. Built-in names and ``org_admin`` are refused."""
        team = _check_team(team)
        if not _may_admin(who, team):
            raise PermissionDeniedError(f"{who.actor} may not declare roles for team {team}")
        names: list[str] = []
        for role in roles:
            if not isinstance(role, str) or not _ROLE.fullmatch(role):
                raise InvalidMappingError(f"role {role!r} must match [a-z][a-z0-9_]*")
            if role == ORG_ADMIN or role in BUILTIN_ROLES:
                raise InvalidMappingError(f"role {role!r} is reserved")
            if role not in names:
                names.append(role)
        self._store.put(TeamScope(team), _ROLES_KEY, {"roles": sorted(names), "by": who.actor})

    # --- mappings ---------------------------------------------------------------------------

    def mapping(self, idp: str, group: str) -> tuple[str | None, str] | None:
        """The stored ``(team, role)`` for a group, or ``None``."""
        item = self._store.get(PLATFORM, _map_key(_check_idp(idp), _check_text("group", group)))
        return _parse(item.data) if item else None

    def set_mapping(
        self, who: Principal, *, idp: str, group: str, team: str | None, role: str
    ) -> None:
        idp, group = _check_idp(idp), _check_text("group", group)
        if team is None:
            if role != ORG_ADMIN:
                raise InvalidMappingError("an org-level mapping can only carry org_admin")
        else:
            team = _check_team(team)
            if role == ORG_ADMIN:
                raise InvalidMappingError("a team group can never be mapped to org_admin")
            if role not in self.roles(team):
                raise InvalidMappingError(f"role {role!r} is not declared for team {team}")
        if not _may_admin(who, team):
            raise PermissionDeniedError(f"{who.actor} may not map groups for {team or 'the org'}")
        self._guard_existing(who, idp, group)
        self._store.put(
            PLATFORM, _map_key(idp, group), {"team": team, "role": role, "by": who.actor}
        )

    def remove_mapping(self, who: Principal, *, idp: str, group: str, team: str | None) -> None:
        idp, group = _check_idp(idp), _check_text("group", group)
        team = None if team is None else _check_team(team)
        if not _may_admin(who, team):
            raise PermissionDeniedError(f"{who.actor} may not unmap groups for {team or 'the org'}")
        self._guard_existing(who, idp, group)
        self._store.delete(PLATFORM, _map_key(idp, group))

    def _guard_existing(self, who: Principal, idp: str, group: str) -> None:
        """A non-org-admin may only touch a group that is unmapped or mapped to their team."""
        item = self._store.get(PLATFORM, _map_key(idp, group))
        current = _parse(item.data) if item else None
        if current is not None and not _may_admin(who, current[0]):
            raise PermissionDeniedError(
                f"{who.actor} may not change a group mapped to {current[0] or 'the org'}"
            )

    # --- users ------------------------------------------------------------------------------

    def disable_user(self, who: Principal, *, idp: str, subject: str) -> None:
        if not who.is_org_admin:
            raise PermissionDeniedError(f"{who.actor} may not disable users: it needs {ORG_ADMIN}")
        key = _disabled_key(_check_idp(idp), _check_text("subject", subject))
        self._store.put(PLATFORM, key, {"by": who.actor})

    def enable_user(self, who: Principal, *, idp: str, subject: str) -> None:
        if not who.is_org_admin:
            raise PermissionDeniedError(f"{who.actor} may not enable users: it needs {ORG_ADMIN}")
        self._store.delete(
            PLATFORM, _disabled_key(_check_idp(idp), _check_text("subject", subject))
        )

    # --- resolution -------------------------------------------------------------------------

    def resolve(self, token: VerifiedToken) -> UserIdentity | ServiceIdentity:
        """Turn a verified token into an identity, from the store as it is right now.

        Raises :class:`UserDisabledError` for a disabled subject and :class:`NoAccessError` for
        a user with no usable mapping. A service identity is returned before any mapping is read.
        """
        if self._store.get(PLATFORM, _disabled_key(token.issuer, token.subject)) is not None:
            raise UserDisabledError("this identity is disabled")
        if is_service_token(token):
            return ServiceIdentity(token.subject, token.issuer, token.subject)
        memberships: set[tuple[str | None, str]] = set()
        known: dict[str, frozenset[str]] = {}
        for group in dict.fromkeys(token.groups):
            if "#" in token.issuer:
                break
            item = self._store.get(PLATFORM, _map_key(token.issuer, group))
            parsed = _parse(item.data) if item else None
            if parsed is None:
                continue
            team, role = parsed
            if team is None:
                if role == ORG_ADMIN:
                    memberships.add((None, role))
                continue
            if role == ORG_ADMIN:
                continue
            if team not in known:
                try:
                    known[team] = self.roles(team)
                except InvalidMappingError:  # a hand-written item naming an impossible team
                    known[team] = frozenset()
            if role in known[team]:
                memberships.add((team, role))
        if not memberships:
            raise NoAccessError("no group of this user is mapped to a team")
        return UserIdentity(token.subject, token.issuer, frozenset(memberships))


def _parse(data: dict[str, Any]) -> tuple[str | None, str] | None:
    team, role = data.get("team"), data.get("role")
    if not isinstance(role, str) or not (team is None or isinstance(team, str)):
        return None
    return team, role
