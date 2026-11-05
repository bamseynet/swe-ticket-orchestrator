"""Jira webhook registration (D6-05, PLAN 10.4): one shared registration per Jira site, kept alive.

* **Ours only.** The IDs this job registered are kept in the ``ORG / JIRAHOOK#<site>`` record. Only
  those are refreshed, replaced or deleted; a webhook someone else registered (another install of
  the app, or by hand) counts toward Jira's limit and is never touched. A crash between Jira's
  answer and the record leaves one unrecorded hook: it counts toward the limit until a person
  deletes it, and the job alerts at the limit.
* **One per site.** Jira allows 5 webhooks per OAuth 2.0 app, per user, per tenant, so teams on a
  site never register their own. ``ProjectBindings`` says which team owns which project, and the
  site's single registration filters ``project in (...)`` over every bound project. Webhook JQL
  supports few clauses, so labels, custom fields and the like are filtered AFTER the re-read, with
  ``ProjectBindings.teams_for`` routing by the re-read ticket's project (never the body's).
* **Refresh.** A webhook lives 30 days from creation or refresh. ``SiteWebhooks.sync`` is meant to
  run daily; it refreshes any webhook with 20 days or less left (so about every 10 days, and a
  job that misses a fortnight still lands inside the expiry). One call refreshes them all.
* **Expiry.** A webhook found expired raises ``jira.webhook.expired`` once, tells the reconciler
  there is a gap (``on_gap``), deletes the dead ones (they count against the limit until deleted)
  and registers afresh. The reconciler sweeps open runs, so events missed meanwhile are late, not
  lost. A site that is bound but has no webhook at all is the same gap (``jira.webhook.missing``),
  except at the very first registration.
* **No gap on change.** A changed binding registers the new filter BEFORE deleting the old one.
  Live hooks are refreshed first, so a hook that is about to be replaced cannot lapse meanwhile. If
  Jira refuses the new one (the limit), our own stale hook is deleted and the registration retried
  once.
* **A gap is remembered before anything changes** (``ORG / JIRAGAP#<site>``), the reconciler is told
  at once, and the note is cleared only when its callback returns. A run that then fails (a refused
  or failed registration) cannot lose the gap; the next run tells again until it is acknowledged.
* **First versus vanished.** Our record is empty on a first registration and non-empty when Jira
  lost a hook of ours. Unbinding every team deletes our hooks and clears the record.
"""

from __future__ import annotations

import contextlib
import logging
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from sto.domain.errors import PermanentError, TransientError
from sto.ingest.core import Metrics
from sto.ingest.jira import SUBSCRIBED_EVENTS
from sto.store.ports import PLATFORM, Absent, ConditionFailedError, Key, Store, VersionIs

log = logging.getLogger(__name__)

DAY = 86_400.0
WEBHOOK_LIFE = 30 * DAY
REFRESH_WHEN_LEFT = 20 * DAY  # refresh at 10 days old, so a job that skips a fortnight is safe
WEBHOOK_LIMIT = 5  # per OAuth 2.0 app, per user, per tenant
PAGE = 100
MAX_PAGES = 50
RECORD_RETRIES = 5

_PROJECT_KEY = re.compile(r"[A-Z][A-Z0-9_]{1,9}", re.ASCII)


class WebhookRefusedError(PermanentError):
    """Jira refused the registration (a bad filter, a second URL): a person must look."""


class WebhookLimitError(WebhookRefusedError):
    """The app's webhook limit is reached: a person must free a slot."""


@dataclass(frozen=True)
class ApiReply:
    status: int
    body: Any


class JiraApi(Protocol):
    """The authenticated REST calls the job makes. The OAuth client (D6-02) implements it; webhook
    registration needs a bearer token, never an API token. ``path`` is below ``/rest/api/3``."""

    def call(self, method: str, path: str, body: Any = None, params: Any = None) -> ApiReply: ...


class Alerts(Protocol):
    def alert(self, name: str, message: str, **details: Any) -> None: ...


def _ids(value: object) -> set[int]:
    if not isinstance(value, list):
        return set()
    return {i for i in value if isinstance(i, int) and not isinstance(i, bool)}


def _valid_project(key: object) -> str:
    if not isinstance(key, str) or not _PROJECT_KEY.fullmatch(key):
        raise ValueError(f"not a Jira project key: {key!r}")
    return key


def webhook_jql(projects: Iterable[str]) -> str:
    """``project in (A, B)``, sorted and deduplicated. Keys are checked so that a bound value can
    never add a clause to the filter."""
    keys = sorted({_valid_project(p) for p in projects})
    if not keys:
        raise ValueError("a webhook filter needs at least one project")
    return f"project in ({', '.join(keys)})"


class ProjectBindings:
    """Which team owns which Jira project on one site. Several teams may share a project."""

    def __init__(self) -> None:
        self._teams: dict[str, set[str]] = {}

    def bind(self, team: str, project: str) -> None:
        if not isinstance(team, str) or not team:
            raise ValueError("a team is a non-empty name")
        self._teams.setdefault(_valid_project(project), set()).add(team)

    def unbind(self, team: str) -> None:
        for project in list(self._teams):
            self._teams[project].discard(team)
            if not self._teams[project]:
                del self._teams[project]

    def projects(self) -> frozenset[str]:
        return frozenset(self._teams)

    def teams_for(self, project: str) -> frozenset[str]:
        """The teams a ticket of ``project`` (as RE-READ from Jira) is routed to."""
        return frozenset(self._teams.get(project, ()))


@dataclass(frozen=True)
class SyncReport:
    registered: int = 0
    refreshed: int = 0
    deleted: int = 0
    expired: int = 0


class SiteWebhooks:
    """The registration job for one Jira site."""

    def __init__(
        self,
        site: str,
        url: str,
        store: Store,
        api: JiraApi,
        bindings: ProjectBindings,
        alerts: Alerts,
        metrics: Metrics,
        *,
        clock: Callable[[], float] = time.time,
        on_gap: Callable[[str], None] = lambda site: None,
    ) -> None:
        self._site, self._url, self._store, self._api = site, url, store, api
        self._bindings, self._alerts, self._metrics = bindings, alerts, metrics
        self._clock, self._on_gap = clock, on_gap

    # --- one run ------------------------------------------------------------------------

    def sync(self) -> SyncReport:
        now = self._clock()
        if self._gap_pending():  # told earlier and not acknowledged, or the run died first
            self._tell_reconciler()
        # The record is read BEFORE the listing: a hook a concurrent run registers meanwhile is in
        # the listing but not in our snapshot (left alone), never in our snapshot but missing from
        # the listing (which would read as vanished).
        owned = self._owned()
        hooks = self._list()
        ours = [h for h in hooks if h["id"] in owned]  # never a hook someone else registered
        expired = [h for h in ours if self._expiry(h) <= now]
        live = [h for h in ours if self._expiry(h) > now]
        if expired:
            self._metrics.incr("webhook.expired", surface=self._surface)
            self._alerts.alert(
                "jira.webhook.expired",
                f"Jira webhook expired on site {self._site}; the reconciler covers the gap",
                site=self._site,
                ids=sorted(h["id"] for h in expired),
            )
            self._gap_known()
        projects = self._bindings.projects()
        if not projects:
            deleted = self._delete(ours)
            self._disown(owned)  # nothing is ours any more: a later bind is a first registration
            return SyncReport(deleted=deleted, expired=len(expired))
        if owned and not ours:
            self._missing()  # we registered one and Jira has none: events were missed
            self._gap_known()
        self._disown(owned - {h["id"] for h in ours})
        # first: a working hook must not lapse while we replace it
        refreshed = self._refresh(live, now)
        jql = webhook_jql(projects)
        events = sorted(SUBSCRIBED_EVENTS)
        keep = [
            h for h in live if h.get("jqlFilter") == jql and sorted(h.get("events") or []) == events
        ]
        stale = [h for h in live if h not in keep]
        extra, keep = keep[1:], keep[:1]  # one registration per site, however it got doubled
        deleted = self._delete(expired)  # dead ones count against the limit until deleted
        registered = 0
        if not keep:
            created = self._try_register(jql, events)
            at_limit = len(hooks) - len(expired) >= WEBHOOK_LIMIT
            if isinstance(created, str) and at_limit and stale:
                # at the limit: free OUR OWN stale hook (never a foreign one) and try once more.
                # Deleting the one that still works opens a gap: the reconciler hears first.
                self._gap_known()
                deleted += self._delete(stale)
                stale = []
                created = self._try_register(jql, events)
            if isinstance(created, str):
                self._refused(created, at_limit)
            registered = 1
        deleted += self._delete([*stale, *extra])
        return SyncReport(registered, refreshed, deleted, len(expired))

    # --- Jira calls -----------------------------------------------------------------------

    @property
    def _surface(self) -> str:
        return f"jira.{self._site}"

    @staticmethod
    def _expiry(hook: dict[str, Any]) -> float:
        stamp = hook.get("expirationDate")
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
            raise PermanentError("jira webhook has no numeric expirationDate")
        return float(stamp) / 1000.0

    def _checked(self, reply: ApiReply, what: str, *ok: int) -> Any:
        if reply.status in ok:
            return reply.body
        if reply.status in (408, 425, 429) or reply.status >= 500:
            raise TransientError(f"jira webhook {what}: status {reply.status}")
        raise PermanentError(f"jira webhook {what}: status {reply.status}")

    def _list(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for page in range(MAX_PAGES):
            reply = self._api.call(
                "GET", "/webhook", params={"startAt": page * PAGE, "maxResults": PAGE}
            )
            body = self._checked(reply, "list", 200)
            values = body.get("values") if isinstance(body, dict) else None
            if not isinstance(values, list):
                raise PermanentError("jira webhook list has no values")
            for value in values:
                ident = value.get("id") if isinstance(value, dict) else None
                if isinstance(ident, bool) or not isinstance(ident, int):
                    raise PermanentError("jira webhook list holds an entry with no integer id")
                out.append(value)
            if body.get("isLast") is not False:
                return out
        raise PermanentError("jira webhook list never ended")

    def _try_register(self, jql: str, events: list[str]) -> int | str:
        """The new webhook's ID, or Jira's reason for refusing it."""
        body = {"url": self._url, "webhooks": [{"events": events, "jqlFilter": jql}]}
        reply = self._api.call("POST", "/webhook", body)
        result = self._checked(reply, "register", 200)
        listed = result.get("webhookRegistrationResult") if isinstance(result, dict) else None
        if not isinstance(listed, list) or len(listed) != 1 or not isinstance(listed[0], dict):
            raise PermanentError("jira webhook registration reply is not one result")
        entry = listed[0]
        ident = entry.get("createdWebhookId")
        if isinstance(ident, int) and not isinstance(ident, bool):
            self._own({ident})
            self._metrics.incr("webhook.registered", surface=self._surface)
            return ident
        errors = entry.get("errors")
        if not (isinstance(errors, list) and errors and all(isinstance(e, str) for e in errors)):
            raise PermanentError("jira webhook registration gave neither an ID nor errors")
        return "; ".join(errors)

    def _refused(self, reason: str, at_limit: bool) -> None:
        self._metrics.incr("webhook.register_refused", surface=self._surface)
        name = "jira.webhook.limit" if at_limit else "jira.webhook.refused"
        self._alerts.alert(
            name, f"Jira refused the webhook for site {self._site}: {reason}", site=self._site
        )
        raise (WebhookLimitError if at_limit else WebhookRefusedError)(reason)

    def _delete(self, hooks: list[dict[str, Any]]) -> int:
        if not hooks:
            return 0
        ids = {h["id"] for h in hooks}
        reply = self._api.call("DELETE", "/webhook", {"webhookIds": sorted(ids)})
        self._checked(reply, "delete", 200, 202)
        self._disown(ids)
        return len(hooks)

    def _refresh(self, hooks: list[dict[str, Any]], now: float) -> int:
        due = [h for h in hooks if self._expiry(h) - now <= REFRESH_WHEN_LEFT]
        if not due:
            return 0
        reply = self._api.call("PUT", "/webhook/refresh", {"webhookIds": [h["id"] for h in due]})
        self._checked(reply, "refresh", 200)
        self._metrics.incr("webhook.refreshed", surface=self._surface)
        return len(due)

    # --- the record of what this job registered ----------------------------------------------

    def _key(self) -> Key:
        return Key("ORG", f"JIRAHOOK#{self._site}")

    def _owned(self) -> set[int]:
        item = self._store.get(PLATFORM, self._key())
        ids = item.data.get("ids") if item else None
        return _ids(ids)

    def _own(self, ids: set[int]) -> None:
        self._change_record(lambda held: held | ids)

    def _disown(self, ids: set[int]) -> None:
        if ids:
            self._change_record(lambda held: held - ids)

    def _change_record(self, change: Callable[[set[int]], set[int]]) -> None:
        """Compare-and-set the ID list; an empty list removes the record (so "first" is first)."""
        for _ in range(RECORD_RETRIES):
            item = self._store.get(PLATFORM, self._key())
            held = _ids(item.data.get("ids")) if item else set()
            new = change(set(held))
            if new == held:
                return
            when = Absent() if item is None else VersionIs(item.version)
            try:
                if new:
                    data = {"site": self._site, "ids": sorted(new)}
                    self._store.put(PLATFORM, self._key(), data, when=when)
                else:
                    self._store.delete(PLATFORM, self._key(), when=when)
                return
            except ConditionFailedError:
                continue  # another run got in between our read and write: merge again
        raise TransientError("jira webhook record kept changing")

    def _missing(self) -> None:
        self._alerts.alert(
            "jira.webhook.missing",
            f"Jira site {self._site} had no webhook although teams are bound; registered again",
            site=self._site,
        )

    def _gap_key(self) -> Key:
        return Key("ORG", f"JIRAGAP#{self._site}")

    def _gap_pending(self) -> bool:
        return self._store.get(PLATFORM, self._gap_key()) is not None

    def _gap_known(self) -> None:
        """Events may have been missed. Remember it BEFORE anything changes, so a run that then
        fails cannot lose it, and tell the reconciler now."""
        with contextlib.suppress(ConditionFailedError):  # already pending
            self._store.put(
                PLATFORM, self._gap_key(), {"site": self._site, "at": self._clock()}, when=Absent()
            )
        self._tell_reconciler()

    def _tell_reconciler(self) -> None:
        """The pending gap stays until the callback returns without raising, then it is cleared."""
        try:
            self._on_gap(self._site)
        except Exception:
            log.exception("webhook gap callback failed", extra={"site": self._site})
            self._metrics.incr("webhook.gap_failed", surface=self._surface)
            return
        self._store.delete(PLATFORM, self._gap_key())
