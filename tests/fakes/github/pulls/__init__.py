"""The fake GitHub's pull requests, merges, refs and commits (D4-19)."""

from fakes.github.auth import Response
from fakes.github.pulls.server import (
    OWNER,
    REPO,
    SOURCES,
    UNSOURCED,
    FakeGitHubPulls,
)

__all__ = ["OWNER", "REPO", "SOURCES", "UNSOURCED", "FakeGitHubPulls", "Response"]
