"""In-memory ``TicketSource``."""

from __future__ import annotations

import json
from dataclasses import replace

from sto.adapters.fake.spy import SpyWriter
from sto.adapters.ports import (
    BoardRef,
    ExternalChange,
    IdempotencyKey,
    IntakeQuery,
    Page,
    RawWebhook,
    Sprint,
    StatusIntent,
    Ticket,
    TicketCapabilities,
    TicketRef,
    TicketSummary,
)
from sto.domain.models import Receipt

_PORT = "ticket_source"


class FakeTicketSource:
    def __init__(self, spy: SpyWriter | None = None) -> None:
        self.capabilities = TicketCapabilities()
        self._spy = spy or SpyWriter()
        self._tickets: dict[TicketRef, Ticket] = {}
        self._comments: dict[TicketRef, list[str]] = {}
        self.sprint: Sprint | None = None

    def add_ticket(self, ticket: Ticket) -> None:
        self._tickets[ticket.ref] = ticket

    def comments(self, ref: TicketRef) -> list[str]:
        return list(self._comments.get(ref, []))

    def get(self, ref: TicketRef) -> Ticket:
        return self._tickets[ref]

    def search(
        self, query: IntakeQuery, cursor: str | None, page_size: int = 50
    ) -> Page[TicketSummary]:
        found = [
            TicketSummary(t.ref, t.title, t.status)
            for t in self._tickets.values()
            if (query.status is None or t.status == query.status)
            and all(label in t.labels for label in query.labels)
        ]
        start = int(cursor) if cursor else 0
        end = start + page_size
        return Page(tuple(found[start:end]), str(end) if end < len(found) else None)

    def parse_event(self, raw: RawWebhook) -> list[ExternalChange]:
        key = json.loads(raw.body or b"{}").get("ticket")
        return [ExternalChange(TicketRef("fake", key))] if key else []

    def comment(self, ref: TicketRef, body: str, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            self._comments.setdefault(ref, []).append(body)
            return self._spy.receipt("comment", f"fake://{ref.key}")

        return self._spy.write(_PORT, "comment", {"ref": ref, "body": body}, key, apply)

    def transition(self, ref: TicketRef, to: StatusIntent, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            self._tickets[ref] = replace(self._tickets[ref], status=to.value)
            return self._spy.receipt("transition", f"fake://{ref.key}")

        return self._spy.write(_PORT, "transition", {"ref": ref, "to": to}, key, apply)

    def current_sprint(self, board: BoardRef) -> Sprint | None:
        return self.sprint
