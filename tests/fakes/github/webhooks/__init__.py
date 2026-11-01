"""The fake GitHub's webhook deliveries (D4-16)."""

from contract.suite import ForgeKind
from fakes.github.webhooks.sender import SECRET, WRONG_SECRET, BodyFactory, FakeWebhooks

__all__ = ["SECRET", "WRONG_SECRET", "BodyFactory", "FakeWebhooks", "ForgeKind"]
