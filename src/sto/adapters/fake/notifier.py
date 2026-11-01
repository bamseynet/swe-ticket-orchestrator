"""In-memory ``Notifier``."""

from __future__ import annotations

from sto.adapters.fake.base import FakeBase, load_json
from sto.adapters.fake.spy import SpyWriter
from sto.adapters.ports import (
    DecisionRequest,
    GateMessage,
    IdempotencyKey,
    MalformedWebhookError,
    NotifierCapabilities,
    RawWebhook,
    RefusedError,
    UnknownRefError,
)
from sto.domain.models import DecisionKind, Receipt


class FakeNotifier(FakeBase):
    def __init__(self, spy: SpyWriter | None = None) -> None:
        super().__init__("notifier", spy)
        self.capabilities = NotifierCapabilities()
        self._messages: dict[str, GateMessage] = {}

    def messages(self, channel: str | None = None) -> list[GateMessage]:
        return [m for m in self._messages.values() if channel is None or m.channel == channel]

    def send(self, message: GateMessage, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            receipt = self._receipt("msg", f"fake://msg/{message.gate_id}")
            self._messages[receipt.external_id] = message
            return receipt

        return self._write("send", {"message": message}, key, apply)

    def update(self, receipt: Receipt, message: GateMessage) -> Receipt:
        """Only messages this fake sent can be updated; the result is a fresh receipt."""

        def apply() -> Receipt:
            if receipt.external_id not in self._messages:
                raise UnknownRefError(f"no message {receipt.external_id!r}")
            if self._messages[receipt.external_id].channel != message.channel:
                raise RefusedError("a sent message cannot move to another channel")
            self._messages[receipt.external_id] = message
            return self._receipt("msg", f"fake://msg/{message.gate_id}", receipt.external_id)

        return self._write("update", {"receipt": receipt, "message": message}, None, apply)

    def parse_action(self, raw: RawWebhook) -> DecisionRequest | None:
        if not raw.body:
            return None
        body = load_json(raw)
        try:
            digest = body.get("subject_digest")  # vetoes may omit it (PLAN 4)
            return DecisionRequest(
                gate_id=body["gate_id"],
                kind=DecisionKind(body["kind"]),
                actor=body["actor"],
                subject_digest=digest,
                comment=body.get("comment", ""),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise MalformedWebhookError("unreadable decision action") from exc
