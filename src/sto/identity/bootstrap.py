"""First org admin (PLAN 9.2, D3-18).

Mappings are data, so something outside the mappings must write the first one. A deployment
parameter names one bootstrap IdP group (``idp`` plus group ID, exact match). A verified user in
that group may call :meth:`Bootstrap.claim` once, naming the group that becomes ``org_admin``
(by default the bootstrap group itself). After that the bootstrap is dead:

* an empty system has exactly one way in: the bootstrap group, in the configured issuer;
* the claim writes a ``BOOTSTRAP#USED`` marker with an ``Absent`` condition, so two racing claims
  cannot both win, and the marker is never deleted, so removing every mapping later does not
  reopen it;
* it is also closed by **any** mapping that exists, however it was written;
* a disabled user, a service identity and a user with the wrong issuer or group are refused;
* the claim is audited through the ``audit`` callback and recorded in the marker (who, when, which
  groups). The run-chained audit log (``sto.audit``) is per run, so wiring this event into an
  org-level audit stream belongs to the caller.

Unverified until D12: that the bootstrap group ID is what Cognito emits for the real IdP.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from sto.config.org_policy import ORG_ADMIN, Principal
from sto.domain.errors import PermanentError
from sto.identity.mapping import (
    NoAccessError,
    RoleMapping,
    ServiceIdentity,
    _check_text,
)
from sto.identity.oidc import VerifiedToken
from sto.store.ports import PLATFORM, Absent, ConditionFailedError, Key, Store

__all__ = ["Bootstrap", "BootstrapRefusedError"]

_USED = Key("ORG", "BOOTSTRAP#USED")
_MAP_PREFIX = "MAP#"


class BootstrapRefusedError(PermanentError):
    """The bootstrap is closed, or this caller is not the bootstrap group."""


class Bootstrap:
    def __init__(
        self,
        store: Store,
        mapping: RoleMapping,
        *,
        idp: str,
        group: str,
        clock: Callable[[], float] = time.time,
        audit: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if not isinstance(idp, str) or not idp:
            raise ValueError("idp must be a non-empty string")
        if not isinstance(group, str) or not group or group != group.strip():
            raise ValueError("the bootstrap group must be a non-empty, trimmed string")
        try:
            mapping._check_idp(idp)
        except PermanentError as exc:
            raise ValueError("the bootstrap idp must be a configured issuer") from exc
        self._store, self._mapping, self._clock, self._audit = store, mapping, clock, audit
        self._idp, self._group = idp, group

    def is_open(self) -> bool:
        """True only while nothing has been claimed and no mapping exists."""
        if self._store.get(PLATFORM, _USED) is not None:
            return False
        return not self._store.query(PLATFORM, "ORG", sk_prefix=_MAP_PREFIX, limit=1).items

    def claim(self, token: VerifiedToken, *, admin_group: str | None = None) -> Principal:
        """Write the first org-admin mapping. Works once. Returns the acting org principal.

        Raises :class:`BootstrapRefusedError`, ``UserDisabledError`` or a ``PermanentError`` for
        a bad ``admin_group``; the bootstrap stays open after any of them.
        """
        if token.issuer != self._idp or self._group not in token.groups:
            raise BootstrapRefusedError("not the bootstrap group")
        try:
            who = self._mapping.resolve(token)  # raises UserDisabledError first
        except NoAccessError:
            pass  # the normal case: nothing is mapped yet
        else:
            if isinstance(who, ServiceIdentity):
                raise BootstrapRefusedError("a service identity cannot bootstrap")
        target = _check_text("admin group", admin_group if admin_group is not None else self._group)
        if not self.is_open():
            raise BootstrapRefusedError("the bootstrap has been used or mappings exist")
        actor = f"{token.issuer}|{token.subject}"
        now = self._clock()
        try:
            self._store.put(
                PLATFORM,
                _USED,
                {"by": actor, "at": now, "bootstrap_group": self._group, "admin_group": target},
                when=Absent(),
            )
        except ConditionFailedError as exc:
            raise BootstrapRefusedError("the bootstrap has been used") from exc
        principal = Principal(actor, frozenset({ORG_ADMIN}))
        try:
            self._mapping.set_mapping(
                principal, idp=self._idp, group=target, team=None, role=ORG_ADMIN
            )
        except Exception:
            self._store.delete(PLATFORM, _USED)  # nothing was granted, so do not burn it
            raise
        if self._audit is not None:
            self._audit(
                {
                    "event": "bootstrap.claimed",
                    "actor": actor,
                    "idp": self._idp,
                    "bootstrap_group": self._group,
                    "admin_group": target,
                    "at": now,
                }
            )
        return principal
