"""The fake GitHub's App auth, rate limits, pagination and errors (D4-16)."""

from contract.suite import RateShape
from fakes.github.auth.server import (
    APP_ID,
    APP_KEY,
    INSTALLATION_ID,
    FakeGitHubAuth,
    Item,
    Response,
)

__all__ = [
    "APP_ID",
    "APP_KEY",
    "INSTALLATION_ID",
    "FakeGitHubAuth",
    "Item",
    "RateShape",
    "Response",
]
