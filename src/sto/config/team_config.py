"""Stored, live ``TeamConfig`` (D2-24): PLAN 7.1 and the ``TEAM#t / CONFIG`` item of PLAN 11.

The document is stored as the text that passed ``load_document`` and is parsed again on every
read, so a stored item can never be looser than the schema, and the next read after a write sees
the change (PLAN 7.4: calendars and budgets are live). A team document holds no floors: the
schema refuses ``min_quorum``, ``mandatory_gate_roles`` and the rest, and refuses ``null`` in
their place, so nothing a team writes can lower an org floor.
"""

from __future__ import annotations

from sto.config.org_policy import (
    ORG_ADMIN,
    PermissionDeniedError,
    Principal,
    Versioned,
    checked_text,
    stored_text,
)
from sto.config.schema import Issue, SchemaError, TeamConfig, load_document
from sto.domain.errors import PermanentError
from sto.store.ports import TEAM_ROOT, Absent, Key, Store, TeamScope, VersionIs

__all__ = [
    "TEAM_ADMIN",
    "TEAM_CONFIG_KEY",
    "TeamConfig",
    "TeamConfigMissingError",
    "TeamConfigStore",
]

TEAM_ADMIN = "team_admin"
TEAM_CONFIG_KEY = Key(TEAM_ROOT, "CONFIG")


class TeamConfigMissingError(PermanentError):
    """The team has no config. A missing config is not "no budget": callers that need one use
    ``TeamConfigStore.require`` so ``None`` cannot be mistaken for a default."""


class TeamConfigStore:
    def __init__(self, store: Store) -> None:
        self._store = store

    def write(
        self, scope: TeamScope, who: Principal, text: str, *, expected_version: int | None
    ) -> TeamConfig:
        """Store ``text`` as the team's config. A team admin of that team, or an org admin.

        ``expected_version`` is the version from ``read_versioned`` this edit was made on
        (``None`` to create it); a write since then fails with ``ConditionFailedError``."""
        if not (who.is_org_admin or (who.team == scope.team and who.has(TEAM_ADMIN))):
            raise PermissionDeniedError(
                f"{who.actor} may not write the config of team {scope.team}: "
                f"it needs {TEAM_ADMIN} in that team or {ORG_ADMIN}"
            )
        doc = self._parse(checked_text(text, "TeamConfig"), scope)
        self._store.put(
            scope,
            TEAM_CONFIG_KEY,
            {"text": text},
            when=Absent() if expected_version is None else VersionIs(expected_version),
        )
        return doc

    def read_versioned(self, scope: TeamScope) -> Versioned[TeamConfig] | None:
        item = self._store.get(scope, TEAM_CONFIG_KEY)
        if item is None:
            return None
        return Versioned(
            self._parse(stored_text(item.data, "TeamConfig"), scope, stored=True), item.version
        )

    def read(self, scope: TeamScope) -> TeamConfig | None:
        current = self.read_versioned(scope)
        return None if current is None else current.document

    def require(self, scope: TeamScope) -> TeamConfig:
        config = self.read(scope)
        if config is None:
            raise TeamConfigMissingError(f"team {scope.team} has no config")
        return config

    @staticmethod
    def _parse(text: str, scope: TeamScope, *, stored: bool = False) -> TeamConfig:
        doc = load_document(text, source=f"TeamConfig {scope.team}")
        if not isinstance(doc, TeamConfig):
            what = (
                "the stored document is not a TeamConfig" if stored else "kind must be TeamConfig"
            )
            raise SchemaError([Issue(1, "kind", what)])
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
        return doc
