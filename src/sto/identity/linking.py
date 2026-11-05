"""Account linking (PLAN 9.2, D3-04).

A person links their Slack, GitHub or Jira account to their SSO identity by completing **that
vendor's OAuth flow while signed in**. That is the only proof accepted. The vendor's answer to the
authorization code is the account ID; an email address, whether the vendor reports it or the user
types it, is never used to link, never stored and never compared (there is no such method).

Flow, each step one :class:`AccountLinking` call:

1. :meth:`~AccountLinking.start` (signed in): issues a **link token**, which is the OAuth ``state``
   and the only thing the vendor redirect carries back. The token is random, shown once, and
   stored only as a hash, together with the SSO user (``issuer|subject``), a hash of the SSO
   session ID, the vendor and an expiry.
2. :meth:`~AccountLinking.complete` (signed in again): refuses unless the token exists, has not
   expired, and the caller is the same SSO user in the same SSO session for the same vendor
   (checked before the vendor is called, so a stranger holding the state cannot use it up). Then
   the vendor exchanges the code for the account ID, and **one transaction** consumes the token,
   writes the link and its reverse lookup, and writes the audit entry. A replayed token finds no
   token item and is refused; two racing completions cannot both win, because the token delete
   carries the version that was read.

Tokens are short-lived (``token_ttl``, at most :data:`MAX_TOKEN_TTL`; the clock is injected) and
links expire too (``link_ttl``): an expired link resolves to nothing, so **an unlinked or expired
account can never decide** (:meth:`~AccountLinking.require_linked` raises, and
:meth:`~AccountLinking.resolve` returns ``None``; both fail closed on a malformed item).

One vendor account belongs to one person. A live link held by someone else refuses a new one
(:class:`AccountClaimedError`); an *expired* one can be taken over, by completing the flow. The
same person completing it again refreshes the expiry.

Unlink (:meth:`~AccountLinking.unlink`) is the owner's, works on an expired link, and writes
``link.removed`` in the same transaction; creation writes ``link.created``. Entries are append-only
items (this module only ever puts them under ``Absent`` and never reads one back to change it)
under the user's partition, numbered by a per-user counter that moves in the same transaction, so
two writes can never share a number. They are **not** in the audit table: its writers are a
registered set (``tests/audit/test_writer_conformance.py``, an invariant that needs an ADR to
change) and its chain is per run, and a link belongs to no run. A tamper-evident user-level chain
is a follow-up for D3-08.

Every write goes through the store port as a conditional transaction (``Absent`` or the version
that was read), retried on a lost race with fresh reads. Items (platform scope; PLAN 11 has
``USER#u / LINK#surface#id``)::

    USER#<actor>  LINK#<vendor>#<account>   the link: expiry, when linked
    USER#<actor>  LINKSEQ                   log counter
    USER#<actor>  LINKLOG#<seq>             the append-only log entries
    ORG           LINKED#<vendor>#<account> reverse lookup: who holds the account
    ORG           LINKTOKEN#<sha256>        a pending token

Unverified until D12: the real Slack, GitHub and Jira OAuth flows (scopes, redirect URIs, the
account ID each returns). Here the vendors are the :class:`VendorOAuth` port, faked in tests.
"""

from __future__ import annotations

import hashlib
import math
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from sto.domain.errors import PermanentError, TransientError
from sto.identity.mapping import InvalidMappingError, UserIdentity, check_text
from sto.store.ports import (
    PLATFORM,
    Absent,
    ConditionFailedError,
    Delete,
    Key,
    Op,
    Put,
    Store,
    VersionIs,
)

__all__ = [
    "MAX_TOKEN_TTL",
    "VENDORS",
    "AccountClaimedError",
    "AccountLinking",
    "Link",
    "LinkContentionError",
    "LinkRefusedError",
    "LinkStateError",
    "LinkStart",
    "LinkTokenExpiredError",
    "LinkTokenInvalidError",
    "LinkTokenMismatchError",
    "LinkedActor",
    "NotLinkedError",
    "UnknownVendorError",
    "VendorAccount",
    "VendorExchangeError",
    "VendorOAuth",
    "actor_of",
]

VENDORS = ("slack", "github", "jira")
MAX_TOKEN_TTL = 900.0
DEFAULT_TOKEN_TTL = 600.0
DEFAULT_LINK_TTL = 30 * 86_400.0
MAX_LINK_TTL = 5 * 365 * 86_400.0
_ATTEMPTS = 5
_ORG = "ORG"
_TOKEN = "LINKTOKEN#"
_LINKED = "LINKED#"
_LINK = "LINK#"
_SEQ = "LINKSEQ"
_LOG = "LINKLOG#"


class LinkRefusedError(PermanentError):
    """Base of every refusal here; the subclass says why."""


class UnknownVendorError(LinkRefusedError):
    """Not one of :data:`VENDORS`."""


class LinkTokenInvalidError(LinkRefusedError):
    """No such token: never issued, already used (a replay) or lost a race to another completion."""


class LinkTokenExpiredError(LinkRefusedError):
    """The token's lifetime is over."""


class LinkTokenMismatchError(LinkRefusedError):
    """The token belongs to another SSO user, another SSO session or another vendor."""


class AccountClaimedError(LinkRefusedError):
    """A live link already ties that vendor account to someone else."""


class NotLinkedError(LinkRefusedError):
    """No live link for that account (never linked, expired, or removed)."""


class LinkStateError(LinkRefusedError):
    """A stored item (the log counter) is not in the shape this module writes: refused, not
    guessed at."""


class LinkContentionError(TransientError):
    """The store kept losing races on this write (not a used token): try again shortly."""


class VendorExchangeError(LinkRefusedError):
    """The vendor refused the code, or answered with an account ID that cannot be used."""


@dataclass(frozen=True)
class VendorAccount:
    """What the vendor says the code belongs to. ``email`` is informational and never used."""

    account_id: str
    email: str | None = None


class VendorOAuth(Protocol):
    """One vendor's OAuth flow. Real ones (D7, D4) hold client secrets and call the vendor; tests
    use fakes. ``exchange`` raises :class:`VendorExchangeError` for a code the vendor refuses.

    What a real adapter must return as ``account_id`` (the identity the link is keyed on):

    * **GitHub:** the immutable numeric user ID, never the login, which can be renamed and
      reclaimed by someone else.
    * **Slack:** an ID scoped by the workspace (``team_id`` plus the user ID), since user IDs are
      only unique within a workspace.
    * **Jira:** Atlassian account IDs are global, so the exchange must also check the site (the
      accessible-resources list) belongs to the org, or a stranger's account could be linked.

    Not yet in this port: PKCE and ``redirect_uri`` binding. The link token is the OAuth
    ``state`` and ``complete`` binds it to the SSO user, session and vendor, but an adapter that
    exchanges a code must still send the registered redirect URI and a PKCE verifier when its
    vendor supports one. Unverified until D12."""

    def authorize_url(self, state: str) -> str: ...

    def exchange(self, code: str) -> VendorAccount: ...


@dataclass(frozen=True)
class LinkStart:
    token: str  # also the OAuth ``state``; shown once
    authorize_url: str
    expires_at: float


@dataclass(frozen=True)
class Link:
    vendor: str
    account_id: str
    linked_at: float
    expires_at: float


@dataclass(frozen=True)
class LinkedActor:
    """The SSO identity a live link resolves to. ``actor`` is ``issuer|subject``."""

    vendor: str
    account_id: str
    issuer: str
    subject: str
    expires_at: float

    @property
    def actor(self) -> str:
        return f"{self.issuer}|{self.subject}"


def actor_of(identity: UserIdentity) -> str:
    """``issuer|subject``, the actor key separation of duties compares."""
    return f"{identity.issuer}|{identity.subject}"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _user_pk(actor: str) -> str:
    return f"USER#{actor}"


def _number(value: object) -> float | None:
    """A finite number, else ``None`` (NaN and infinity never read as a usable time)."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


class AccountLinking:
    def __init__(
        self,
        store: Store,
        *,
        vendors: Mapping[str, VendorOAuth],
        clock: Callable[[], float] = time.time,
        token_ttl: float = DEFAULT_TOKEN_TTL,
        link_ttl: float = DEFAULT_LINK_TTL,
    ) -> None:
        if not 0 < token_ttl <= MAX_TOKEN_TTL:
            raise ValueError(f"token_ttl must be above 0 and at most {MAX_TOKEN_TTL} seconds")
        if not (math.isfinite(link_ttl) and 0 < link_ttl <= MAX_LINK_TTL):
            raise ValueError(f"link_ttl must be finite, above 0 and at most {MAX_LINK_TTL} seconds")
        unknown = set(vendors) - set(VENDORS)
        if unknown:
            raise ValueError(f"unknown vendors {sorted(unknown)}; use {VENDORS}")
        self._store, self._vendors, self._clock = store, dict(vendors), clock
        self.token_ttl, self.link_ttl = float(token_ttl), float(link_ttl)

    # --- reads ------------------------------------------------------------------------------

    def resolve(self, vendor: str, account_id: str) -> LinkedActor | None:
        """The SSO identity holding this vendor account, or ``None``: unlinked, expired or a
        malformed item all give ``None``, so nothing downstream can treat them as linked."""
        self._vendor(vendor)
        item = self._store.get(PLATFORM, _reverse_key(vendor, account_id))
        return self._live(vendor, account_id, item.data) if item else None

    def require_linked(self, vendor: str, account_id: str) -> LinkedActor:
        found = self.resolve(vendor, account_id)
        if found is None:
            raise NotLinkedError(f"that {vendor} account is not linked to anyone")
        return found

    def links_of(self, identity: UserIdentity) -> list[Link]:
        """The caller's live links."""
        now, out, cursor = self._clock(), [], None
        while True:
            page = self._store.query(
                PLATFORM, _user_pk(actor_of(identity)), sk_prefix=_LINK, cursor=cursor
            )
            for item in page.items:
                link = _link_from(item.data)
                if link is not None and now < link.expires_at:
                    out.append(link)
            cursor = page.cursor
            if cursor is None:
                return out

    # --- start and complete -----------------------------------------------------------------

    def start(self, identity: UserIdentity, session: str, vendor: str) -> LinkStart:
        oauth = self._vendor(vendor)
        actor, session_hash = actor_of(identity), _session_hash(session)
        token = secrets.token_urlsafe(32)
        now = self._clock()
        expires_at = now + self.token_ttl
        data = {
            "user": actor,
            "session": session_hash,
            "vendor": vendor,
            "issued_at": now,
            "expires_at": expires_at,
        }
        self._store.transact(PLATFORM, [Put(_token_key(token), data, Absent())])
        return LinkStart(token, oauth.authorize_url(token), expires_at)

    def complete(
        self, identity: UserIdentity, session: str, vendor: str, token: str, code: str
    ) -> Link:
        oauth = self._vendor(vendor)
        actor, session_hash = actor_of(identity), _session_hash(session)
        self._read_token(token, actor, session_hash, vendor)  # refuse before calling the vendor
        account = oauth.exchange(code)
        account_id = _account_id(account)
        for attempt in range(_ATTEMPTS):
            # fresh reads each time: a lost race may have used the token up or taken the account
            version = self._read_token(token, actor, session_hash, vendor)
            link, ops = self._link_ops(identity, vendor, account_id, token, version, session_hash)
            try:
                self._store.transact(PLATFORM, ops)
            except ConditionFailedError:
                if attempt == _ATTEMPTS - 1:
                    # a used-up or expired token says so; otherwise it is only contention
                    self._read_token(token, actor, session_hash, vendor)
                    raise LinkContentionError("the store is busy; try completing again") from None
                continue
            return link
        raise AssertionError("unreachable")  # pragma: no cover

    # --- unlink -----------------------------------------------------------------------------

    def unlink(self, identity: UserIdentity, vendor: str, account_id: str) -> None:
        """Remove the caller's own link (live or expired) and audit it. A link that is not the
        caller's is refused the same way as one that does not exist."""
        self._vendor(vendor)
        actor = actor_of(identity)
        for attempt in range(_ATTEMPTS):
            link = self._store.get(PLATFORM, _link_key(actor, vendor, account_id))
            reverse = self._store.get(PLATFORM, _reverse_key(vendor, account_id))
            owner = f"{reverse.data.get('issuer')}|{reverse.data.get('subject')}" if reverse else ""
            if link is None or reverse is None or owner != actor:
                raise NotLinkedError(f"that {vendor} account is not linked to you")
            ops: list[Op] = [
                Delete(link.key, VersionIs(link.version)),
                Delete(reverse.key, VersionIs(reverse.version)),
                *self._audit(
                    actor,
                    actor,
                    "link.removed",
                    {"vendor": vendor, "account_id": account_id, "owner": actor},
                ),
            ]
            try:
                self._store.transact(PLATFORM, ops)
            except ConditionFailedError:
                if attempt == _ATTEMPTS - 1:
                    raise LinkContentionError("the store is busy; try unlinking again") from None
                continue
            return

    # --- internals --------------------------------------------------------------------------

    def _vendor(self, vendor: str) -> VendorOAuth:
        oauth = self._vendors.get(vendor) if isinstance(vendor, str) else None
        if oauth is None:
            raise UnknownVendorError(f"no linking for vendor {vendor!r}")
        return oauth

    def _live(self, vendor: str, account_id: str, data: dict[str, Any]) -> LinkedActor | None:
        issuer, subject = data.get("issuer"), data.get("subject")
        expires = _number(data.get("expires_at"))
        if not (isinstance(issuer, str) and isinstance(subject, str) and expires is not None):
            return None
        if not (issuer and subject) or self._clock() >= expires:
            return None
        return LinkedActor(vendor, account_id, issuer, subject, expires)

    def _read_token(self, token: str, actor: str, session_hash: str, vendor: str) -> int:
        """Check the token and return its version. Nothing is written on a refusal."""
        item = self._store.get(PLATFORM, _token_key(token)) if isinstance(token, str) else None
        if item is None:
            raise LinkTokenInvalidError("this link token is not valid (unknown or already used)")
        expires = _number(item.data.get("expires_at"))
        if expires is None:
            raise LinkTokenInvalidError("this link token is not valid")
        if self._clock() >= expires:
            raise LinkTokenExpiredError("this link token has expired; start again")
        bound = (item.data.get("user"), item.data.get("session"), item.data.get("vendor"))
        if bound != (actor, session_hash, vendor):
            raise LinkTokenMismatchError(
                "this link token was issued to another user, session or vendor"
            )
        return item.version

    def _link_ops(
        self,
        identity: UserIdentity,
        vendor: str,
        account_id: str,
        token: str,
        token_version: int,
        session_hash: str,
    ) -> tuple[Link, list[Op]]:
        actor, now = actor_of(identity), self._clock()
        reverse_key = _reverse_key(vendor, account_id)
        reverse = self._store.get(PLATFORM, reverse_key)
        ops: list[Op] = [Delete(_token_key(token), VersionIs(token_version))]
        detail: dict[str, Any] = {"vendor": vendor, "account_id": account_id, "owner": actor}
        if reverse is None:
            reverse_when: Absent | VersionIs = Absent()
        else:
            held = self._live(vendor, account_id, reverse.data)
            previous = f"{reverse.data.get('issuer')}|{reverse.data.get('subject')}"
            if held is not None and held.actor != actor:
                raise AccountClaimedError(f"that {vendor} account is linked to someone else")
            if held is None and not _well_formed(reverse.data):
                raise AccountClaimedError(f"that {vendor} account has an unreadable claim")
            reverse_when = VersionIs(reverse.version)
            if previous != actor:  # an expired claim by someone else: replace it
                detail["replaced_owner"] = previous
                old = self._store.get(PLATFORM, _link_key(previous, vendor, account_id))
                if old is not None:
                    ops.append(Delete(old.key, VersionIs(old.version)))
                # the old owner's log records the loss, with the new owner as the actor
                gone = {"vendor": vendor, "account_id": account_id, "owner": previous,
                        "reason": "replaced"}  # fmt: skip
                ops.extend(self._audit(previous, actor, "link.removed", gone))
        expires_at = now + self.link_ttl
        link = Link(vendor, account_id, now, expires_at)
        mine = self._store.get(PLATFORM, _link_key(actor, vendor, account_id))
        ops.append(
            Put(
                _link_key(actor, vendor, account_id),
                {
                    "vendor": vendor,
                    "account_id": account_id,
                    "linked_at": now,
                    "expires_at": expires_at,
                    "session": session_hash,
                },  # fmt: skip
                Absent() if mine is None else VersionIs(mine.version),
            )
        )
        ops.append(
            Put(
                reverse_key,
                {
                    "issuer": identity.issuer,
                    "subject": identity.subject,
                    "linked_at": now,
                    "expires_at": expires_at,
                },  # fmt: skip
                reverse_when,
            )
        )
        ops.extend(self._audit(actor, actor, "link.created", detail))
        return link, ops

    def _audit(self, owner: str, actor: str, action: str, data: dict[str, Any]) -> list[Op]:
        """The counter bump and the append-only entry, for the caller's transaction."""
        seq_key = Key(_user_pk(owner), _SEQ)
        head = self._store.get(PLATFORM, seq_key)
        if head is None:
            seq = 1
        else:
            last = head.data.get("seq")
            if type(last) is not int or last < 0:
                raise LinkStateError("the link log counter is unreadable; refusing to write")
            seq = last + 1
        entry = {"seq": seq, "at": int(self._clock() * 1000), "action": action, "actor": actor,
                 "data": data}  # fmt: skip
        return [
            Put(seq_key, {"seq": seq}, Absent() if head is None else VersionIs(head.version)),
            Put(Key(_user_pk(owner), f"{_LOG}{seq:012d}"), entry, Absent()),
        ]


def _session_hash(session: object) -> str:
    if not isinstance(session, str) or not session:
        raise ValueError("an SSO session is required to link an account")
    return _digest(session)


def _account_id(account: VendorAccount) -> str:
    try:
        return check_text("account_id", account.account_id)
    except InvalidMappingError as e:
        raise VendorExchangeError(f"the vendor gave an unusable account ID: {e}") from None


def _token_key(token: str) -> Key:
    return Key(_ORG, f"{_TOKEN}{_digest(token)}")


def _reverse_key(vendor: str, account_id: str) -> Key:
    return Key(_ORG, f"{_LINKED}{vendor}#{account_id}")


def _link_key(actor: str, vendor: str, account_id: str) -> Key:
    return Key(_user_pk(actor), f"{_LINK}{vendor}#{account_id}")


def _well_formed(data: dict[str, Any]) -> bool:
    return (
        isinstance(data.get("issuer"), str)
        and isinstance(data.get("subject"), str)
        and _number(data.get("expires_at")) is not None
    )


def _link_from(data: dict[str, Any]) -> Link | None:
    vendor, account = data.get("vendor"), data.get("account_id")
    linked, expires = _number(data.get("linked_at")), _number(data.get("expires_at"))
    if not (isinstance(vendor, str) and isinstance(account, str)):
        return None
    if linked is None or expires is None:
        return None
    return Link(vendor, account, linked, expires)
