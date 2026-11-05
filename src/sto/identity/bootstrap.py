"""First org admin (PLAN 9.2, D3-18).

Mappings are data, so something outside the mappings must write the first one. A deployment
parameter names one bootstrap IdP group (``idp`` plus group ID, exact match). A verified user in
that group may call :meth:`Bootstrap.claim` once. The claim maps **that configured group** to
``org_admin`` (the caller chooses nothing), and the bootstrap is then dead:

* an empty system has exactly one way in: the bootstrap group, in the configured issuer;
* the marker (``BOOTSTRAP#USED``) and the org-level mapping are written in **one**
  ``Store.transact``, both conditioned on ``Absent``, so racing claims have one winner and a
  claim is all or nothing. The marker is never deleted, so removing every mapping later does not
  reopen the bootstrap;
* it is also closed by **any** mapping that exists, however it was written;
* a disabled user, a service identity and a user with the wrong issuer or group are refused.

Audit. The marker is the durable audit record: who (``by``), when (``at``), ``idp`` and
``group``. It commits in the same transaction as the grant, so a grant cannot exist without it.
The required ``audit`` callback is a notification sent after commit; if it raises, the error is
logged and the claim still succeeds, because the grant and its durable record are committed.

If the store reports an unknown outcome the claim re-reads: when the marker names this claimant
and the mapping exists it finishes as a success; when neither exists the bootstrap is still open
and :class:`BootstrapRetryError` (transient) is raised. After any refusal or error other than a
committed claim, the bootstrap is still open.

Private use, not done here: this module imports ``_check_text`` and calls ``_check_idp`` from
``mapping.py`` and copies its ``ORG``/``MAP#`` key layout, because ``mapping.py`` is not in this
issue's files. ``test_mapping_written_through_role_mapping_closes_bootstrap`` fails if the layout
drifts.

Unverified until D12: that the bootstrap group ID is what Cognito emits for the real IdP.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from sto.config.org_policy import ORG_ADMIN, Principal
from sto.domain.errors import PermanentError, TransientError
from sto.identity.mapping import NoAccessError, RoleMapping, ServiceIdentity, _check_text
from sto.identity.oidc import VerifiedToken
from sto.store.ports import (
    PLATFORM,
    Absent,
    ConditionFailedError,
    Key,
    Put,
    Store,
    TransactionOutcomeUnknownError,
)

__all__ = ["Bootstrap", "BootstrapRefusedError", "BootstrapRetryError"]

_log = logging.getLogger(__name__)
_USED = Key("ORG", "BOOTSTRAP#USED")
_MAP_PREFIX = "MAP#"


class BootstrapRefusedError(PermanentError):
    """The bootstrap is closed, or this caller is not the bootstrap group."""


class BootstrapRetryError(TransientError):
    """The store could not say whether the claim committed; it did not. Try again."""


class Bootstrap:
    def __init__(
        self,
        store: Store,
        mapping: RoleMapping,
        *,
        idp: str,
        group: str,
        audit: Callable[[dict[str, Any]], None],
        clock: Callable[[], float] = time.time,
    ) -> None:
        try:
            _check_text("the bootstrap group", group)
            mapping._check_idp(idp)
        except PermanentError as exc:
            raise ValueError(f"bad bootstrap configuration: {exc}") from exc
        self._store, self._mapping, self._clock, self._audit = store, mapping, clock, audit
        self._idp, self._group = idp, group

    def is_open(self) -> bool:
        """True only while nothing has been claimed and no mapping exists."""
        if self._store.get(PLATFORM, _USED) is not None:
            return False
        return not self._store.query(PLATFORM, "ORG", sk_prefix=_MAP_PREFIX, limit=1).items

    def claim(self, token: VerifiedToken) -> Principal:
        """Map the bootstrap group to ``org_admin``. Works once. Returns the acting principal.

        Raises :class:`BootstrapRefusedError`, ``UserDisabledError`` or
        :class:`BootstrapRetryError`; the bootstrap stays open after each of them.
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
        if not self.is_open():
            raise BootstrapRefusedError("the bootstrap has been used or mappings exist")
        actor = f"{token.issuer}|{token.subject}"
        now = self._clock()
        marker = {"by": actor, "at": now, "idp": self._idp, "group": self._group}
        grant = {"team": None, "role": ORG_ADMIN, "by": actor, "at": now}
        map_key = Key("ORG", f"{_MAP_PREFIX}{self._idp}#{self._group}")
        try:
            self._store.transact(
                PLATFORM,
                [Put(_USED, marker, when=Absent()), Put(map_key, grant, when=Absent())],
            )
        except ConditionFailedError as exc:
            raise BootstrapRefusedError("the bootstrap has been used") from exc
        except TransactionOutcomeUnknownError as exc:
            if not self._committed(map_key, actor):
                raise BootstrapRetryError("outcome unknown and nothing was written") from exc
        self._notify({"event": "bootstrap.claimed", **marker})
        return Principal(actor, frozenset({ORG_ADMIN}))

    def _committed(self, map_key: Key, actor: str) -> bool:
        """After an unknown outcome: True if this claimant's claim is there in full."""
        used = self._store.get(PLATFORM, _USED)
        if used is None:
            return False  # one transaction: no marker means no mapping, and still open
        if used.data.get("by") != actor or self._store.get(PLATFORM, map_key) is None:
            raise BootstrapRefusedError("the bootstrap has been used")
        return True

    def _notify(self, event: dict[str, Any]) -> None:
        try:
            self._audit(event)
        except Exception:
            _log.exception("bootstrap audit callback failed; the claim is committed")
