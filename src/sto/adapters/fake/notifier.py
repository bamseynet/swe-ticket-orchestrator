"""In-memory ``Notifier``."""

from __future__ import annotations

from sto.adapters.fake.spy import SpyWriter
from sto.adapters.ports import (
    DecisionRequest,
    GateMessage,
    IdempotencyKey,
    NotifierCapabilities,
    RawWebhook,
)
from sto.domain.models import Receipt

_PORT = "notifier"


class FakeNotifier:
    def __init__(self, spy: SpyWriter | None = None) -> None:
        self.capabilities = NotifierCapabilities()
        self._spy = spy or SpyWriter()
        self._messages: dict[str, GateMessage] = {}

    def messages(self) -> list[GateMessage]:
        return list(self._messages.values())

    def send(self, message: GateMessage, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            receipt = self._spy.receipt("msg", f"fake://msg/{message.gate_id}")
            self._messages[receipt.external_id] = message
            return receipt

        return self._spy.write(_PORT, "send", {"message": message}, key, apply)

    def update(self, receipt: Receipt, message: GateMessage) -> Receipt:
        self._spy.record(_PORT, "update", {"receipt": receipt, "message": message})
        self._messages[receipt.external_id] = message
        return receipt

    def parse_action(self, raw: RawWebhook) -> DecisionRequest | None:
        return None
