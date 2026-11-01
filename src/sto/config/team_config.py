"""Stored, live ``TeamConfig`` (D2-24): PLAN 7.1 and the ``TEAM#t / CONFIG`` item of PLAN 11.

The document is stored as the text that passed ``load_document`` and is parsed again on every
read, so a stored item can never be looser than the schema, and the next read after a write sees
the change (PLAN 7.4: calendars and budgets are live). A team document holds no floors: the
schema refuses ``min_quorum``, ``mandatory_gate_roles`` and the rest, and refuses ``null`` in
their place, so nothing a team writes can lower an org floor.
"""

from __future__ import annotations

from sto.config.org_policy import ORG_ADMIN, PermissionDeniedError, Principal
from sto.config.schema import Issue, SchemaError, TeamConfig, load_document
from sto.store.ports import TEAM_ROOT, Absent, Key, Store, TeamScope, VersionIs

__all__ = ["TEAM_ADMIN", "TEAM_CONFIG_KEY", "TeamConfig", "TeamConfigStore"]

TEAM_ADMIN = "team_admin"
TEAM_CONFIG_KEY = Key(TEAM_ROOT, "CONFIG")


class TeamConfigStore:
    def __init__(self, store: Store) -> None:
        self._store = store

    def write(self, scope: TeamScope, who: Principal, text: str) -> TeamConfig:
        """Store ``text`` as the team's config. A team admin of that team, or an org admin."""
        if not (who.has(ORG_ADMIN) or (who.team == scope.team and who.has(TEAM_ADMIN))):
            raise PermissionDeniedError(
                f"{who.actor} may not write the config of team {scope.team}: "
                f"it needs {TEAM_ADMIN} in that team or {ORG_ADMIN}"
            )
        doc = load_document(text, source=f"TeamConfig {scope.team}")
        if not isinstance(doc, TeamConfig):
            raise SchemaError([Issue(1, "kind", "kind must be TeamConfig")])
        if doc.metadata.team != scope.team:
            raise SchemaError(
                [
                    Issue(
                        None,
                        "metadata.team",
                        f"this config is for team {scope.team}, not {doc.metadata.team}",
                    )
                ]
            )
        current = self._store.get(scope, TEAM_CONFIG_KEY)
        self._store.put(
            scope,
            TEAM_CONFIG_KEY,
            {"text": text},
            when=Absent() if current is None else VersionIs(current.version),
        )
        return doc

    def read(self, scope: TeamScope) -> TeamConfig | None:
        item = self._store.get(scope, TEAM_CONFIG_KEY)
        if item is None:
            return None
        doc = load_document(str(item.data["text"]), source=f"TeamConfig {scope.team}")
        if not isinstance(doc, TeamConfig):
            raise SchemaError([Issue(1, "kind", "the stored document is not a TeamConfig")])
        return doc
