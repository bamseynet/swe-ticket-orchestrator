"""Overlays and flattening (D2-02).

A ``WorkflowOverlay`` is a JSON Merge Patch (RFC 7386) over the ``Workflow`` template it extends
(PLAN 7.1): maps merge key by key, lists replace whole, and ``null`` removes a key. Stage order has
no meaning, so the stage map is merged like any other map. ``flatten`` applies the patch, checks
the result and returns a plain ``Workflow`` with the layer that set each value.

What a ``null`` may not do. Removal is how a team would weaken a gate without writing a weaker
value, so a few keys are floors (``FLOORS``): ``separation_of_duties: null`` is not "no rule" and
``fail_closed: null`` is not "fall back to False", both are errors that name the floor. A
mandatory gate (``pre_push``, ``review``, ``qa``) cannot be removed or turned into something else,
whichever way the patch tries it. The check is on the patch, not only on the result, so it holds
even when the template did not have the key.

Rules that guard against particular mistakes:

* The merged document is re-validated as a ``Workflow``. Nothing here uses ``exclude_none``,
  which would silently drop every removal from the patch (``WorkflowOverlay.to_patch`` keeps
  them). The template is dumped with ``exclude_unset``: a plain ``model_dump`` writes every
  default and every ``None``, which the strict models then refuse.
* Nulls nested in a ``with`` agree with ``load_document``. In a patch a null removes a key, and
  inside an object that is new to the target it is dropped (RFC 7386), so none is stored. One left
  anywhere in the merged document (in a list, or from a template built in code) is refused, as the
  loader refuses it.
* An ``env.deploy_preview`` stage never names a production deployment in its ``with``.

Provenance maps every value of the merged document to the layer that set it: the template
reference (``standard@1``) or ``overlay:<name>``. A value is the overlay's when the patch wrote it
or any object above it; a list is one value. Keys the patch removed are listed in ``removed``.
Defaults the schema fills in are in neither: only explicit values have a layer.
"""

from __future__ import annotations

import copy
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pydantic import ValidationError

from sto.config.schema import (
    MANDATORY_GATES,
    Issue,
    Loc,
    SchemaError,
    Workflow,
    WorkflowOverlay,
    _fmt_path,
    _issues_from,
    _null_issues,
)

__all__ = [
    "FLOORS",
    "Flattened",
    "OverlayError",
    "Provenance",
    "flatten",
    "merge_patch",
]

Path = tuple[str, ...]
_ANY = "*"

# Keys a patch may set but never remove. ``*`` stands for any stage id. Each value is why.
FLOORS: Mapping[Path, str] = MappingProxyType(
    {
        ("start",): "a workflow must start somewhere",
        ("stages",): "a workflow needs its stages",
        ("limits",): "every run has limits",
        ("limits", "max_steps_per_run"): "every run has a step limit",
        ("limits", "max_run_age"): "every run has an age limit",
        ("stages", _ANY, "requires_gates"): (
            "a gated effect waits for its gates, and no gates would mean none"
        ),
        ("stages", _ANY, "fail_closed"): "removing it would fall back to False",
        ("stages", _ANY, "block_on"): "a review panel always has a severity that blocks",
        (
            "stages",
            _ANY,
            "required",
        ): "a review panel or checks stage always names what is required",
        ("stages", _ANY, "gate", "eligible_roles"): "a gate always names who may decide",
        ("stages", _ANY, "gate", "decisions"): "a gate always names what may be decided",
        ("stages", _ANY, "gate", "decision_surfaces"): "a gate always names where it is decided",
        ("stages", _ANY, "gate", "quorum"): "removing it would fall back to a single approval",
        ("stages", _ANY, "gate", "path_owners"): "removing it would drop the owners' approval",
        ("stages", _ANY, "gate", "separation_of_duties"): (
            "removing it would let the author, requester or committer decide"
        ),
        ("stages", _ANY, "gate", "separation_of_duties", "not"): (
            "removing it would let the author, requester or committer decide"
        ),
    }
)

_PRODUCTION_WORDS = frozenset({"prod", "production", "prd", "live"})


class OverlayError(SchemaError):
    """An overlay that cannot be flattened. Each issue names the path that is refused."""

    def __reduce__(self) -> tuple[Any, ...]:
        return (OverlayError, (self.issues, self.source))


@dataclass(frozen=True)
class Provenance:
    """The layer behind every value of a flattened document, keyed by its path.

    ``leaves`` has one entry per value: a scalar, a list, or an empty object. ``removed`` lists
    the keys the overlay removed from the template.
    """

    leaves: Mapping[Path, str]
    removed: tuple[Path, ...]

    def source(self, path: Path) -> str:
        """The layer that set the value at ``path``. ``KeyError`` for a path with no value."""
        return self.leaves[path]


@dataclass(frozen=True)
class Flattened:
    workflow: Workflow
    provenance: Provenance


# --- RFC 7386 --------------------------------------------------------------------------------


def _merge(
    target: Any,
    patch: Any,
    path: Path,
    written: set[Path],
    removed: list[Path],
) -> Any:
    if not isinstance(patch, dict):
        written.add(path)
        return copy.deepcopy(patch)
    if isinstance(target, dict):
        out: dict[str, Any] = target
    else:  # a patch object over an absent or non-object value starts from empty: nulls drop
        written.add(path)
        out = {}
    for key, value in patch.items():
        if value is None:
            if key in out:
                del out[key]
                removed.append((*path, key))
        else:
            out[key] = _merge(out.get(key), value, (*path, key), written, removed)
    return out


def merge_patch(target: Any, patch: Any) -> Any:
    """RFC 7386 JSON Merge Patch. Returns a new value; neither argument is changed."""
    return _merge(copy.deepcopy(target), patch, (), set(), [])


# --- checks ----------------------------------------------------------------------------------


def _where(path: Path) -> str:
    return _fmt_path(path)


def _floor_reason(path: Path) -> str | None:
    for floor, reason in FLOORS.items():
        if len(floor) == len(path) and all(
            f in (_ANY, p) for f, p in zip(floor, path, strict=True)
        ):
            return reason
    return None


def _null_floors(patch: Any, path: Path = ()) -> list[Issue]:
    found: list[Issue] = []
    if not isinstance(patch, dict):
        return found
    for key, value in patch.items():
        here = (*path, key)
        if value is None:
            reason = _floor_reason(here)
            if reason is not None:
                found.append(
                    Issue(
                        None,
                        _where(here),
                        f"null cannot remove this: it is a floor ({reason}); "
                        "change its value instead",
                    )
                )
        else:
            found.extend(_null_floors(value, here))
    return found


def _mandatory_gates(template: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    stages = template.get("stages")
    if isinstance(stages, dict):
        for sid, stage in stages.items():
            gate = stage.get("gate") if isinstance(stage, dict) else None
            is_gate = isinstance(stage, dict) and stage.get("kind") == "gate"
            if is_gate and isinstance(gate, dict) and gate.get("type") in MANDATORY_GATES:
                out[sid] = gate["type"]
    return out


def _mandatory_issues(template: Mapping[str, Any], merged: Mapping[str, Any]) -> list[Issue]:
    found: list[Issue] = []
    stages = merged.get("stages")
    for sid, gate_type in _mandatory_gates(template).items():
        stage = stages.get(sid) if isinstance(stages, dict) else None
        gate = stage.get("gate") if isinstance(stage, dict) else None
        same = (
            isinstance(stage, dict)
            and stage.get("kind") == "gate"
            and isinstance(gate, dict)
            and gate.get("type") == gate_type
        )
        if not same:
            found.append(
                Issue(
                    None,
                    _where(("stages", sid)),
                    f"{sid} is a mandatory {gate_type} gate (floor: pre_push, review and qa "
                    "gates are mandatory); an overlay cannot remove it or turn it into "
                    "something else",
                )
            )
    return found


def _nulls(value: Any) -> list[Issue]:
    """Nulls the loader refuses in a Workflow. The same function, so the two cannot disagree.

    A null item inside a list is a value to the loader (it is the model that judges it), and
    only a null mapping value is refused.
    """
    return [Issue(None, i.path, i.message) for i in _null_issues(value, {})]


def _present(value: Any, path: Loc = ()) -> dict[Loc, int]:
    """Every path of a document, so a validation error can be resolved to a path.

    The value is a line number the resolver wants but a document built in memory has none; the
    callers drop it from the issues.
    """
    found: dict[Loc, int] = {path: 1}
    if isinstance(value, dict):
        for k, v in value.items():
            found.update(_present(v, (*path, k)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            found.update(_present(v, (*path, i)))
    return found


def _strings(value: Any, path: Path) -> list[tuple[Path, str]]:
    """Every key and string value under ``value``, with where it is."""
    found: list[tuple[Path, str]] = []
    if isinstance(value, str):
        found.append((path, value))
    elif isinstance(value, dict):
        for key, item in value.items():
            found.append(((*path, key), str(key)))
            found.extend(_strings(item, (*path, key)))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            found.extend(_strings(item, (*path, str(i))))
    return found


def _scripts(word: str) -> set[str]:
    """The scripts of a word's letters (LATIN, GREEK, CYRILLIC, ...), from Unicode names."""
    return {unicodedata.name(c, "?").split(" ")[0] for c in word if c.isalpha()}


_BOUNDS = re.compile(
    r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])"
)


def _names_production(text: str) -> bool:
    """Whether ``text`` has a word that means production.

    Compatibility forms (full-width letters) are folded first. Words are split at separators, at
    lower-to-upper case and between letters and digits, so ``prodEnv`` and ``prod1`` count. A word
    that mixes scripts (Latin with a Greek omicron) is refused, since it is written to look like
    another word.
    """
    folded = unicodedata.normalize("NFKC", text)
    for token in re.split(r"[\W_]+", folded):
        if len(_scripts(token)) > 1:
            return True
        if any(w.lower() in _PRODUCTION_WORDS for w in _BOUNDS.sub(" ", token).split()):
            return True
    return False


def _preview_issues(merged: Mapping[str, Any]) -> list[Issue]:
    found: list[Issue] = []
    stages = merged.get("stages")
    if not isinstance(stages, dict):
        return found
    for sid, stage in stages.items():
        if not (isinstance(stage, dict) and stage.get("effect") == "env.deploy_preview"):
            continue
        for path, text in _strings(stage.get("with"), ("stages", sid, "with")):
            if _names_production(text):
                found.append(
                    Issue(
                        None,
                        _where(path),
                        "env.deploy_preview cannot name a production deployment: "
                        "it runs before QA, on unmerged code, and only for a preview",
                    )
                )
                break
    return found


# --- flatten ---------------------------------------------------------------------------------


def _leaves(value: Any, path: Path = ()) -> list[Path]:
    if isinstance(value, dict) and value:
        return [p for k, v in value.items() for p in _leaves(v, (*path, k))]
    return [path]


def _provenance(
    merged: Mapping[str, Any], written: set[Path], removed: Sequence[Path], base: str, top: str
) -> Provenance:
    leaves: dict[Path, str] = {}
    for leaf in _leaves(merged):
        mine = any(leaf[:i] in written for i in range(len(leaf) + 1))
        leaves[leaf] = top if mine else base
    return Provenance(MappingProxyType(leaves), tuple(removed))


def flatten(
    template: Workflow,
    overlay: WorkflowOverlay,
    *,
    template_ref: str,
    require_publishable: bool = True,
) -> Flattened:
    """Apply ``overlay`` to the ``template`` it extends and validate the result as a Workflow.

    ``template_ref`` is the ``name@version`` the caller resolved ``template`` from. It must equal
    the overlay's ``extends``, so provenance never records a version the template did not come
    from. The result is schema-valid only: V1-V17 must run on it before it is stored or
    published.

    Raises ``OverlayError`` listing every problem found. With ``require_publishable`` (the
    default, because flattening happens at publish) the result must also have an ``intake`` and
    a ``repo``, which a template may leave to its overlays.
    """
    base_ref = template_ref
    top = f"overlay:{overlay.metadata.name}"
    source = overlay.metadata.name
    wanted = base_ref.partition("@")[0]
    if base_ref != overlay.extends:
        raise OverlayError(
            [
                Issue(
                    None,
                    "extends",
                    f"this overlay extends {overlay.extends!r} but the template given is "
                    f"{base_ref!r}",
                )
            ],
            source,
        )
    if template.metadata.name != wanted:
        raise OverlayError(
            [
                Issue(
                    None,
                    "extends",
                    f"this overlay extends {base_ref!r} but the template given is "
                    f"{template.metadata.name!r}",
                )
            ],
            source,
        )

    patch = overlay.to_patch()  # nulls kept: they are the removals
    problems = _null_floors(patch)
    document = template.model_dump(mode="json", by_alias=True, exclude_unset=True)
    original = copy.deepcopy(document)
    written: set[Path] = set()
    removed: list[Path] = []
    merged = _merge(document, patch, (), written, removed)
    merged["metadata"] = overlay.metadata.model_dump(mode="json")
    written.add(("metadata",))

    problems += _mandatory_issues(original, merged)
    problems += _nulls(merged)
    problems += _preview_issues(merged)
    if problems:
        raise OverlayError(problems, source)

    try:
        workflow = Workflow.model_validate(merged)
    except ValidationError as err:
        found = _issues_from(err, merged, _present(merged), discriminated=True)
        raise OverlayError([Issue(None, i.path, i.message) for i in found], source) from None
    if require_publishable:
        missing = workflow.missing_for_publish()
        if missing:
            raise OverlayError(
                [
                    Issue(None, key, f"{key} is required to publish: set it in the overlay")
                    for key in missing
                ],
                source,
            )
    return Flattened(workflow, _provenance(merged, written, removed, base_ref, top))
