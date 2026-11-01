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
    UnknownRefError,
)
from sto.domain.models import DecisionKind, Receipt


class FakeNotifier(FakeBase):
    def __init__(self, spy: SpyWriter | None = None) -> None:
        super().__init__("notifier", spy)
        self.capabilities = NotifierCapabilities()
        self._messages: dict[str, GateMessage] = {}

    def messages(self) -> list[GateMessage]:
        return list(self._messages.values())

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
            self._messages[receipt.external_id] = message
            return self._receipt("msg", f"fake://msg/{message.gate_id}", receipt.external_id)

        return self._write("update", {"receipt": receipt, "message": message}, None, apply)

    def parse_action(self, raw: RawWebhook) -> DecisionRequest | None:
        if not raw.body:
            return None
        body = load_json(raw)
        try:
            return DecisionRequest(
                gate_id=str(body["gate_id"]),
                kind=DecisionKind(body["kind"]),
                actor=str(body["actor"]),
                subject_digest=str(body["subject_digest"]),
                comment=str(body.get("comment", "")),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise MalformedWebhookError("unreadable decision action") from exc
