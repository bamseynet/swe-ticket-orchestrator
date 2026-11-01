"""The fake GitHub's App auth, rate limits, pagination and errors (D4-16)."""

from contract.suite import RateShape
from fakes.github.auth.server import (
    APP_ID,
    APP_KEY,
    CLIENT_ID,
    INSTALLATION_ID,
    INSTALLATION_PERMISSIONS,
    INSTALLATION_REPOS,
    FakeGitHubAuth,
    Grant,
    Item,
    Response,
)

__all__ = [
    "APP_ID",
    "APP_KEY",
    "CLIENT_ID",
    "INSTALLATION_PERMISSIONS",
    "INSTALLATION_REPOS",
    "INSTALLATION_ID",
    "FakeGitHubAuth",
    "Grant",
    "Item",
    "RateShape",
    "Response",
]
