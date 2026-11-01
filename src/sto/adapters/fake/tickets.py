"""In-memory ``TicketSource``."""

from __future__ import annotations

from dataclasses import replace

from sto.adapters.fake.base import FakeBase, parse_changes
from sto.adapters.fake.spy import SpyWriter
from sto.adapters.ports import (
    BoardRef,
    ChangeKind,
    ExternalChange,
    IdempotencyKey,
    IntakeQuery,
    Page,
    RawWebhook,
    RefusedError,
    Sprint,
    StatusIntent,
    Ticket,
    TicketCapabilities,
    TicketRef,
    TicketSummary,
    UnknownRefError,
)
from sto.domain.models import Receipt


class FakeTicketSource(FakeBase):
    _WRITES = frozenset({"comment", "transition"})

    def __init__(self, spy: SpyWriter | None = None, *, page_size: int = 50) -> None:
        super().__init__("ticket_source", spy)
        self.capabilities = TicketCapabilities()
        self.page_size = page_size
        self.sprint: Sprint | None = None
        self._tickets: dict[TicketRef, Ticket] = {}
        self._comments: dict[TicketRef, list[str]] = {}

    def add_ticket(self, ticket: Ticket) -> None:
        self._tickets[ticket.ref] = ticket

    def edit(self, ref: TicketRef, editor: str, **changes: str) -> None:
        """Test control: someone edits the ticket (title, body, ...); it records who."""
        self._tickets[ref] = replace(self._ticket(ref), editor=editor, **changes)  # type: ignore[arg-type]

    def comments(self, ref: TicketRef) -> list[str]:
        return list(self._comments.get(ref, []))

    def _ticket(self, ref: TicketRef) -> Ticket:
        try:
            return self._tickets[ref]
        except KeyError:
            raise UnknownRefError(f"no ticket {ref}") from None

    def get(self, ref: TicketRef) -> Ticket:
        return self._ticket(ref)

    def search(self, query: IntakeQuery, cursor: str | None) -> Page[TicketSummary]:
        found = [
            TicketSummary(t.ref, t.title, t.status)
            for t in self._tickets.values()
            if (query.status is None or t.status == query.status)
            and all(label in t.labels for label in query.labels)
            and (query.project is None or t.project == query.project)
            and (not query.issue_types or t.issue_type in query.issue_types)
        ]
        try:
            start = int(cursor) if cursor else 0
        except ValueError:
            raise RefusedError(f"bad cursor {cursor!r}") from None
        end = start + self.page_size
        return Page(tuple(found[start:end]), str(end) if end < len(found) else None)

    def parse_event(self, raw: RawWebhook) -> list[ExternalChange]:
        return parse_changes(raw, frozenset({ChangeKind.TICKET}))

    def comment(self, ref: TicketRef, body: str, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            self._ticket(ref)
            self._comments.setdefault(ref, []).append(body)
            return self._receipt("comment", f"fake://{ref.key}")

        return self._write("comment", {"ref": ref, "body": body}, key, apply)

    def transition(self, ref: TicketRef, to: StatusIntent, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            ticket = self._ticket(ref)
            self._noop = ticket.status == to.value  # already there is success (PLAN 6.3)
            self._tickets[ref] = replace(ticket, status=to.value)
            return self._receipt("transition", f"fake://{ref.key}")

        return self._write("transition", {"ref": ref, "to": to}, key, apply)

    def current_sprint(self, board: BoardRef) -> Sprint | None:
        return self.sprint
