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

An issuer containing ``|`` is refused at construction: actors are ``issuer|subject`` and separation
of duties compares them exactly, so a ``|`` in an issuer could make two identities share a key.
Bootstrap and other callers use the public helpers :func:`check_text`, :func:`map_key`,
:meth:`RoleMapping.check_idp` and :meth:`RoleMapping.has_any_mapping`, never private names.

``idp`` means the token issuer, compared exactly. Under ADR-0008 every upstream IdP federated into
the Cognito pool shares one ``iss``, so ``idp`` is the broker, group IDs from different upstream
IdPs share one namespace, and a disable is keyed by the pool ``sub``. Provider separation comes
from D3-12 prefixing group IDs with their provider. ``idp`` must be one of the configured
issuers, so a mapping or disable written under a misspelt issuer is refused instead of silently
never matching. Mapping and disable records store who and when; the audit entry belongs to D3-05.

Writes are guarded: a new mapping needs the item to be absent and a change needs the version that
was read, so two admins racing for one group cannot overwrite each other (the loser gets
``ConditionFailedError``). Group IDs and subjects over :data:`MAX_NAME_BYTES` are refused on
write; on read a group that long cannot have a mapping and is skipped.

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
service: that fails closed. The rule recognises Cognito M2M tokens only: Auth0 (``sub`` like
``x@clients``, ``gty``) and Okta (``cid``) M2M tokens would resolve as users, so another broker
needs its own rule, and D3-03 denies services by default on every route. Unverified until D12-10:
that a real M2M token has ``sub == client_id`` and that a real user token never does.
"""

from __future__ import annotations

import re
import time
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from sto.config.org_policy import ORG_ADMIN, PermissionDeniedError, Principal
from sto.domain.errors import PermanentError
from sto.identity.oidc import VerifiedToken
from sto.store.ports import PLATFORM, Absent, Condition, Key, Store, TeamScope, VersionIs

__all__ = [
    "BUILTIN_ROLES",
    "MAX_NAME_BYTES",
    "InvalidMappingError",
    "NoAccessError",
    "RoleMapping",
    "ServiceIdentity",
    "UserDisabledError",
    "UserIdentity",
    "check_text",
    "is_service_token",
    "map_key",
]

BUILTIN_ROLES = ("developer", "reviewer", "qa", "team_admin", "auditor")
TEAM_ADMIN = "team_admin"
MAX_NAME_BYTES = 400  # "DISABLED#<idp>#<subject>" stays under the 1024-byte sort key
_ROLE = re.compile(r"[a-z][a-z0-9_]*", re.ASCII)
_BAD_ISSUER_CHARS = frozenset("#|")  # "#" splits keys; "|" splits the issuer|subject actor key
_ORG_PK = "ORG"
_MAP = "MAP#"
_DISABLED = "DISABLED#"
_ROLES_KEY = Key("TEAM", "ROLES")
_ANY = object()  # "no team given": a removal passes its team, a write does not


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


def _too_long(value: str) -> bool:
    return len(value.encode("utf-8", "surrogatepass")) > MAX_NAME_BYTES


def check_text(label: str, value: object) -> str:
    """Return ``value`` if it is a usable name, else raise :class:`InvalidMappingError`.

    Non-empty ``str``, at most :data:`MAX_NAME_BYTES` bytes, no surrounding whitespace, no control
    or other Unicode ``C*`` characters. Exact: no folding or trimming."""
    if not isinstance(value, str) or not value:
        raise InvalidMappingError(f"{label} must be a non-empty string")
    if _too_long(value):
        raise InvalidMappingError(f"{label} is longer than {MAX_NAME_BYTES} bytes")
    if value != value.strip():
        raise InvalidMappingError(f"{label} must not have surrounding whitespace")
    if any(unicodedata.category(c).startswith("C") for c in value):
        raise InvalidMappingError(f"{label} must not contain control characters")
    return value


def _check_team(team: object) -> str:
    if isinstance(team, str) and _too_long(team):
        raise InvalidMappingError(f"team is longer than {MAX_NAME_BYTES} bytes")
    try:
        return TeamScope(team).team  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise InvalidMappingError(f"bad team: {exc}") from exc


def map_key(idp: str, group: str) -> Key:
    return Key(_ORG_PK, f"{_MAP}{idp}#{group}")


def _disabled_key(idp: str, subject: str) -> Key:
    return Key(_ORG_PK, f"{_DISABLED}{idp}#{subject}")


def _may_admin(who: Principal, team: str | None) -> bool:
    if who.is_org_admin:
        return True
    return team is not None and who.team == team and who.has(TEAM_ADMIN)


class RoleMapping:
    def __init__(
        self,
        store: Store,
        *,
        issuers: Iterable[str],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store, self._clock = store, clock
        if isinstance(issuers, str):
            raise TypeError("issuers must be a collection of strings, not one string")
        self._issuers = frozenset(issuers)
        if not self._issuers:
            raise ValueError("at least one issuer is required")
        for issuer in self._issuers:
            try:
                check_text("issuer", issuer)  # same rules separation of duties applies
            except InvalidMappingError as exc:
                raise ValueError(f"bad issuer: {exc}") from exc
            if _BAD_ISSUER_CHARS.intersection(issuer):
                raise ValueError("issuers must be short non-empty strings without '#' or '|'")

    @property
    def store(self) -> Store:
        """The store every read and write here goes through."""
        return self._store

    def has_any_mapping(self) -> bool:
        """True if any mapping item is stored, however it was written."""
        return bool(self._store.query(PLATFORM, _ORG_PK, sk_prefix=_MAP, limit=1).items)

    def check_idp(self, idp: object) -> str:
        """``idp`` is a configured issuer, exactly as :meth:`resolve` compares it."""
        if not isinstance(idp, str) or idp not in self._issuers:
            raise InvalidMappingError("idp is not a configured issuer")
        return idp

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
        item = self._store.get(PLATFORM, map_key(self.check_idp(idp), check_text("group", group)))
        return _parse(item.data) if item else None

    def set_mapping(
        self, who: Principal, *, idp: str, group: str, team: str | None, role: str
    ) -> None:
        idp, group = self.check_idp(idp), check_text("group", group)
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
        when = self._guard_existing(who, idp, group)
        self._store.put(
            PLATFORM,
            map_key(idp, group),
            {"team": team, "role": role, "by": who.actor, "at": self._clock()},
            when=when,
        )

    def remove_mapping(self, who: Principal, *, idp: str, group: str, team: str | None) -> None:
        idp, group = self.check_idp(idp), check_text("group", group)
        team = None if team is None else _check_team(team)
        if not _may_admin(who, team):
            raise PermissionDeniedError(f"{who.actor} may not unmap groups for {team or 'the org'}")
        when = self._guard_existing(who, idp, group, team=team)
        self._store.delete(PLATFORM, map_key(idp, group), when=when)

    def _guard_existing(
        self,
        who: Principal,
        idp: str,
        group: str,
        *,
        team: object = _ANY,
    ) -> Condition:
        """Check the group is unmapped or one ``who`` may change, and return the condition the
        write must carry: absent, or the version read here (so a racing write makes it fail).

        With ``team`` given (a removal) the stored team must equal it."""
        item = self._store.get(PLATFORM, map_key(idp, group))
        if item is None:
            return Absent()
        current = _parse(item.data)
        stored_team = current[0] if current else None
        if current is not None and not _may_admin(who, stored_team):
            raise PermissionDeniedError(
                f"{who.actor} may not change a group mapped to {stored_team or 'the org'}"
            )
        if team is not _ANY and current is not None and team != stored_team:
            raise InvalidMappingError("the group is mapped to a different team")
        return VersionIs(item.version)

    # --- users ------------------------------------------------------------------------------

    def disable_user(self, who: Principal, *, idp: str, subject: str) -> None:
        if not who.is_org_admin:
            raise PermissionDeniedError(f"{who.actor} may not disable users: it needs {ORG_ADMIN}")
        key = _disabled_key(self.check_idp(idp), check_text("subject", subject))
        self._store.put(PLATFORM, key, {"by": who.actor, "at": self._clock()})

    def enable_user(self, who: Principal, *, idp: str, subject: str) -> None:
        if not who.is_org_admin:
            raise PermissionDeniedError(f"{who.actor} may not enable users: it needs {ORG_ADMIN}")
        self._store.delete(
            PLATFORM, _disabled_key(self.check_idp(idp), check_text("subject", subject))
        )

    # --- resolution -------------------------------------------------------------------------

    def resolve(self, token: VerifiedToken) -> UserIdentity | ServiceIdentity:
        """Turn a verified token into an identity, from the store as it is right now.

        Raises :class:`UserDisabledError` for a disabled subject and :class:`NoAccessError` for
        a user with no usable mapping. A service identity is returned before any mapping is read.
        """
        if token.issuer not in self._issuers:
            raise NoAccessError("the token issuer is not configured")
        if _too_long(token.subject):
            raise NoAccessError("subject is too long to look up")
        if self._store.get(PLATFORM, _disabled_key(token.issuer, token.subject)) is not None:
            raise UserDisabledError("this identity is disabled")
        if is_service_token(token):
            return ServiceIdentity(token.subject, token.issuer, token.subject)
        memberships: set[tuple[str | None, str]] = set()
        known: dict[str, frozenset[str]] = {}
        for group in dict.fromkeys(token.groups):
            if _too_long(group):
                continue  # writes refuse such a group, so it cannot have a mapping
            item = self._store.get(PLATFORM, map_key(token.issuer, group))
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
