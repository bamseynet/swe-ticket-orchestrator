"""Prompt rendering (D5-03, threat T2).

One pass, in our code, with no framework substitution (ADR-0013). Untrusted text is wrapped in an
``<untrusted source="...">`` frame, and anything inside it that looks like our frame tag is
neutralised so it cannot close (or fake) a frame. Templates are versioned and hashed, and the hashes
go into run records.

Placeholders are ``{{name}}``. A single ``re.sub`` pass fills them, so inserted values are never
scanned again, and single braces such as ``{feedback}`` are never special.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from sto.domain.errors import PermanentError

FRAME_TAG = "untrusted"

_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
_SOURCE_RE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_PLACEHOLDER_RE = re.compile(r"\{\{([a-z][a-z0-9_]*)\}\}")
# Any `<` that starts our frame tag, open or close: optional whitespace and slash around the name,
# in any case. The name must end at a word boundary, so `<untrustedfoo>` is left alone.
_FRAME_TAG_RE = re.compile(rf"<(?=\s*/?\s*{FRAME_TAG}\b)", re.IGNORECASE)


class PromptRenderError(PermanentError):
    """A template or its inputs are invalid. Fails the step; retrying cannot help."""


def neutralise(text: str) -> str:
    """Escape the ``<`` of every frame-tag lookalike, leaving other text untouched."""
    return _FRAME_TAG_RE.sub("&lt;", text)


@dataclass(frozen=True)
class Untrusted:
    """Text from outside our control (ticket, comments, repo, tool output). Always framed."""

    text: str
    source: str

    def __post_init__(self) -> None:
        if not _SOURCE_RE.fullmatch(self.source):
            raise PromptRenderError(f"invalid untrusted source label: {self.source!r}")

    def framed(self) -> str:
        return f'<{FRAME_TAG} source="{self.source}">\n{neutralise(self.text)}\n</{FRAME_TAG}>'


@dataclass(frozen=True)
class PromptTemplate:
    name: str
    version: str
    text: str

    def __post_init__(self) -> None:
        if not _NAME_RE.fullmatch(self.name):
            raise PromptRenderError(f"invalid prompt name: {self.name!r}")
        if not self.version or not self.version.strip():
            raise PromptRenderError("prompt version is required")
        for match in re.finditer(r"\{\{(.*?)\}\}", self.text, re.DOTALL):
            if not _NAME_RE.fullmatch(match.group(1)):
                raise PromptRenderError(f"invalid placeholder: {match.group(0)!r}")

    @property
    def placeholders(self) -> frozenset[str]:
        return frozenset(_PLACEHOLDER_RE.findall(self.text))

    @property
    def sha256(self) -> str:
        """Digest over name, version and text, length-prefixed so fields cannot blur together."""
        h = hashlib.sha256()
        for part in (self.name, self.version, self.text):
            data = part.encode()
            h.update(len(data).to_bytes(8, "big"))
            h.update(data)
        return h.hexdigest()


@dataclass(frozen=True)
class RenderedPrompt:
    name: str
    version: str
    template_sha256: str
    text: str

    @property
    def rendered_sha256(self) -> str:
        return hashlib.sha256(self.text.encode()).hexdigest()

    def record(self) -> dict[str, str]:
        """What a run record stores to identify the prompt that was used."""
        return {
            "name": self.name,
            "version": self.version,
            "template_sha256": self.template_sha256,
            "rendered_sha256": self.rendered_sha256,
        }


def render(template: PromptTemplate, **values: str | Untrusted) -> RenderedPrompt:
    """Fill ``template`` in one pass. ``str`` is trusted code-side text; ``Untrusted`` is framed."""
    wanted = template.placeholders
    given = set(values)
    if wanted - given:
        raise PromptRenderError(f"missing values: {sorted(wanted - given)}")
    if given - wanted:
        raise PromptRenderError(f"unexpected values: {sorted(given - wanted)}")

    def fill(match: re.Match[str]) -> str:
        value = values[match.group(1)]
        return value.framed() if isinstance(value, Untrusted) else value

    text = _PLACEHOLDER_RE.sub(fill, template.text)
    return RenderedPrompt(template.name, template.version, template.sha256, text)
