"""Jira webhook registration (D6-05, PLAN 10.4): one shared registration per Jira site, kept alive.

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
* Jira is the source of truth: the job lists the registrations on each run. The only thing kept
  is a marker that this site has been registered once, so an empty list means "vanished", not
  "new".
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
from sto.store.ports import PLATFORM, Absent, ConditionFailedError, Key, Store

log = logging.getLogger(__name__)

DAY = 86_400.0
WEBHOOK_LIFE = 30 * DAY
REFRESH_WHEN_LEFT = 20 * DAY  # refresh at 10 days old, so a job that skips a fortnight is safe
WEBHOOK_LIMIT = 5  # per OAuth 2.0 app, per user, per tenant
PAGE = 100
MAX_PAGES = 50

_PROJECT_KEY = re.compile(r"[A-Z][A-Z0-9_]{1,9}", re.ASCII)


class WebhookLimitError(PermanentError):
    """The app's webhook limit is reached, or registration was refused: a person must act."""


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
        hooks = self._list()
        projects = self._bindings.projects()
        expired = [h for h in hooks if self._expiry(h) <= now]
        live = [h for h in hooks if self._expiry(h) > now]
        gap = False
        if expired:
            ids = sorted(h["id"] for h in expired)
            self._metrics.incr("webhook.expired", surface=self._surface)
            self._alerts.alert(
                "jira.webhook.expired",
                f"Jira webhook expired on site {self._site}; the reconciler covers the gap",
                site=self._site,
                ids=ids,
            )
            gap = True
        if not projects:
            return SyncReport(deleted=self._delete(hooks), expired=len(expired))
        jql = webhook_jql(projects)
        events = sorted(SUBSCRIBED_EVENTS)
        keep = [
            h for h in live if h.get("jqlFilter") == jql and sorted(h.get("events", [])) == events
        ]
        stale = [h for h in live if h not in keep]
        extra, keep = keep[1:], keep[:1]  # one registration per site, however it got doubled
        registered = 0
        if not keep:
            if not hooks and self._registered_before():
                self._missing()  # it was there once and is gone: events were missed
                gap = True
            self._delete(expired)  # dead ones count against the limit until deleted
            expired = []
            keep = [self._register(jql, events)]
            self._remember()
            registered = 1
        deleted = self._delete([*expired, *stale, *extra])
        refreshed = self._refresh(keep, now) if registered == 0 else 0
        if gap:
            self._tell_reconciler()
        return SyncReport(registered, refreshed, deleted, len(hooks) - len(live))

    # --- Jira calls -----------------------------------------------------------------------

    @property
    def _surface(self) -> str:
        return f"jira.{self._site}"

    @staticmethod
    def _expiry(hook: dict[str, Any]) -> float:
        return float(hook["expirationDate"]) / 1000.0

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
            out.extend(v for v in values if isinstance(v, dict))
            if body.get("isLast") is not False:
                return out
        raise PermanentError("jira webhook list never ended")

    def _register(self, jql: str, events: list[str]) -> dict[str, Any]:
        body = {"url": self._url, "webhooks": [{"events": events, "jqlFilter": jql}]}
        reply = self._api.call("POST", "/webhook", body)
        result = self._checked(reply, "register", 200)
        (entry,) = result["webhookRegistrationResult"]
        if "createdWebhookId" not in entry:
            reason = "; ".join(entry.get("errors", ["refused"]))
            self._metrics.incr("webhook.register_refused", surface=self._surface)
            self._alerts.alert(
                "jira.webhook.limit",
                f"Jira refused the webhook for site {self._site}: {reason}",
                site=self._site,
            )
            raise WebhookLimitError(reason)
        self._metrics.incr("webhook.registered", surface=self._surface)
        # a fresh one is as good as just refreshed: it carries its full life
        return {"id": entry["createdWebhookId"]}

    def _delete(self, hooks: list[dict[str, Any]]) -> int:
        if not hooks:
            return 0
        reply = self._api.call("DELETE", "/webhook", {"webhookIds": [h["id"] for h in hooks]})
        self._checked(reply, "delete", 200, 202)
        return len(hooks)

    def _refresh(self, hooks: list[dict[str, Any]], now: float) -> int:
        due = [h for h in hooks if self._expiry(h) - now <= REFRESH_WHEN_LEFT]
        if not due:
            return 0
        reply = self._api.call("PUT", "/webhook/refresh", {"webhookIds": [h["id"] for h in due]})
        self._checked(reply, "refresh", 200)
        self._metrics.incr("webhook.refreshed", surface=self._surface)
        return len(due)

    def _key(self) -> Key:
        return Key("ORG", f"JIRAHOOK#{self._site}")

    def _registered_before(self) -> bool:
        return self._store.get(PLATFORM, self._key()) is not None

    def _remember(self) -> None:
        with contextlib.suppress(ConditionFailedError):  # already marked
            self._store.put(PLATFORM, self._key(), {"site": self._site}, when=Absent())

    def _missing(self) -> None:
        self._alerts.alert(
            "jira.webhook.missing",
            f"Jira site {self._site} had no webhook although teams are bound; registered again",
            site=self._site,
        )

    def _tell_reconciler(self) -> None:
        try:
            self._on_gap(self._site)
        except Exception:
            log.exception("webhook gap callback failed", extra={"site": self._site})
            self._metrics.incr("webhook.gap_failed", surface=self._surface)
