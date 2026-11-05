"""Publishing and pinning (D2-07; PLAN 7.1 and 7.4).

Publishing turns a team's document into a flattened, validated, immutable workflow *version*, and
gives it a **manifest digest** over everything that decides how a run behaves: the flattened
workflow, the agent profiles (with their outcomes), the effect catalog, and the system prompts. A
run pins that digest when it starts. Old digests stay addressable, so a later publish or a changed
profile can never strand a run with an edge that no longer exists.

Only the shape is pinned. ``TeamConfig`` and ``OrgPolicy`` are never part of the digest or the
stored version: they are read from the store at decision and effect time (PLAN 7.4), so a
tightened floor reaches a pinned run on its next read.

The module is split the way the design is:

* ``prepare`` and ``manifest_digest`` are pure: parse, flatten, run V1-V17, size-check, digest.
  Nothing here touches a store, so publish, dry-run and migrate (D2-19) can share it.
* ``Publisher`` and ``load_pinned`` are the edge. Every read and write goes through the store
  port, so the memory, SQLite and DynamoDB stores give the same answers.

Storage (PLAN 11): ``TEAM#t / WF#name#v`` holds the flattened workflow, its digest and who
published it; ``MANIFEST#digest / META`` (platform scope) holds the profiles, effects and prompts.
Both are written with ``Absent()``, so neither is ever replaced. The manifest item is named by the
digest of the whole bundle, so two identical publishes share one item. ``load_pinned`` recomputes
the digest from what it read and refuses a mismatch, so an item altered after the fact cannot
change what a run does.

V17 is called with the team of the scope being published to (the caller's verified scope), never
the ``metadata.team`` of the file; a file naming another team is refused by V17 itself.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from sto.config.manifest import Manifest
from sto.config.org_policy import (
    ORG_ADMIN,
    OrgPolicyStore,
    PermissionDeniedError,
    Principal,
    check_org_required_gates,
)
from sto.config.overlays import flatten
from sto.config.schema import (
    Issue,
    OrgPolicy,
    SchemaError,
    TeamConfig,
    Workflow,
    WorkflowOverlay,
    load_document,
)
from sto.config.team_config import TEAM_ADMIN, TeamConfigStore
from sto.config.validate_gates import check_gate_dominance
from sto.config.validate_structure import validate_structure
from sto.domain.errors import PermanentError
from sto.store.ports import (
    PLATFORM,
    TEAM_ROOT,
    Absent,
    ConditionFailedError,
    Key,
    Store,
    TeamScope,
    canonical_data,
)

__all__ = [
    "MAX_FLATTENED_BYTES",
    "MAX_PROMPT_BYTES",
    "MAX_PUBLISH_BYTES",
    "Pin",
    "Pinned",
    "PinnedCorruptError",
    "PinnedMissingError",
    "Prepared",
    "Published",
    "Publisher",
    "SchemaError",
    "load_pinned",
    "manifest_digest",
    "prepare",
]

# The loader has no size limit (D2-24 limits only the stored live documents), so publish does.
# The input text and the flattened result are bounded separately: a small overlay on a large
# template flattens to something bigger. All stay well under the store's 400 KiB item limit,
# which is not a SchemaError.
MAX_PUBLISH_BYTES = 128 * 1024
MAX_FLATTENED_BYTES = 256 * 1024
MAX_PROMPT_BYTES = 32 * 1024
# profiles + effects + prompts share one stored item
MAX_MANIFEST_ITEM_BYTES = 300 * 1024
_ATTEMPTS = 8
_ALGORITHM = "sha256"

Resolver = Callable[[str], tuple[str, Workflow]]


class PinnedMissingError(PermanentError):
    """A pinned version or manifest is not in the store. Never replaced by a default."""


class PinnedCorruptError(PermanentError):
    """What the store holds for a pin does not hash to the pinned digest."""


@dataclass(frozen=True)
class Pin:
    """What a run keeps: enough to find its version, and the digest that proves it is the one."""

    team: str
    name: str
    version: int
    digest: str


@dataclass(frozen=True)
class Prepared:
    workflow: Workflow
    document: Mapping[str, Any]  # the flattened workflow as stored
    digest: str


@dataclass(frozen=True)
class Published:
    pin: Pin
    workflow: Workflow


@dataclass(frozen=True)
class Pinned:
    workflow: Workflow
    manifest: Manifest
    prompts: Mapping[str, str]


# --- pure ------------------------------------------------------------------------------------


def _refuse(*issues: Issue) -> SchemaError:
    return SchemaError(list(issues), "publish")


def _bytes(text: str) -> int:
    return len(text.encode("utf-8", "surrogatepass"))


def _workflow_document(wf: Workflow) -> dict[str, Any]:
    # exclude_unset, never a plain dump: a plain dump of a Workflow is refused on re-validation
    return canonical_data(wf.model_dump(mode="json", by_alias=True, exclude_unset=True))


def _manifest_document(manifest: Manifest) -> dict[str, Any]:
    dump = manifest.model_dump(mode="json", by_alias=True)
    # a hold dumps as integer seconds but loads only from a duration, so store it as one
    for spec in dump["effects"].values():
        spec["hold"] = f"{spec['hold']}s"
    return canonical_data({"profiles": dump["profiles"], "effects": dump["effects"]})


def _bundle_digest(
    workflow: Mapping[str, Any], manifest: Mapping[str, Any], prompts: Mapping[str, str]
) -> str:
    """Digest of the stored forms. Sorted keys and fixed separators make it independent of
    insertion order; the prompts are keyed by profile, so moving a prompt changes it."""
    body = {
        "workflow": workflow,
        "profiles": manifest["profiles"],
        "effects": manifest["effects"],
        "prompts": dict(prompts),
    }
    text = json.dumps(
        canonical_data(body), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return f"{_ALGORITHM}:{hashlib.sha256(text.encode('ascii')).hexdigest()}"


def manifest_digest(workflow: Workflow, manifest: Manifest, prompts: Mapping[str, str]) -> str:
    """The digest a run pins: flattened workflow, profiles, effects and system prompts."""
    return _bundle_digest(_workflow_document(workflow), _manifest_document(manifest), prompts)


def _check_prompts(prompts: object) -> dict[str, str]:
    if not isinstance(prompts, Mapping):
        raise _refuse(Issue(None, "prompts", "prompts must be a map of profile name to text"))
    issues: list[Issue] = []
    for name, text in prompts.items():
        if not isinstance(name, str) or not name:
            issues.append(Issue(None, "prompts", "a prompt needs a profile name"))
        elif not isinstance(text, str):
            issues.append(Issue(None, f"prompts.{name}", "a prompt must be text"))
        elif _bytes(text) > MAX_PROMPT_BYTES:
            issues.append(
                Issue(
                    None,
                    f"prompts.{name}",
                    f"the prompt is {_bytes(text)} bytes; the limit is {MAX_PROMPT_BYTES} bytes",
                )
            )
    if issues:
        raise _refuse(*issues)
    return {str(k): str(v) for k, v in prompts.items()}


def _flatten(text: str, resolve_template: Resolver) -> Workflow:
    doc = load_document(text, source="publish")
    if isinstance(doc, WorkflowOverlay):
        ref, template = resolve_template(doc.extends)
        # flatten itself refuses a ref that differs from the overlay's ``extends``
        return flatten(template, doc, template_ref=ref).workflow
    if isinstance(doc, Workflow):
        missing = doc.missing_for_publish()
        if missing:
            raise _refuse(
                *(
                    Issue(None, k, f"{k} is required to publish: set it in the document")
                    for k in missing
                )
            )
        return doc
    raise _refuse(Issue(1, "kind", "kind must be Workflow or WorkflowOverlay to publish"))


def prepare(
    text: str,
    *,
    scope: TeamScope,
    resolve_template: Resolver,
    manifest: Manifest,
    policy: OrgPolicy,
    prompts: Mapping[str, str],
    sandbox_images: Collection[str] | None = None,
    team_config: TeamConfig | None = None,
) -> Prepared:
    """Flatten ``text`` and run every static check. Raises ``SchemaError`` listing the problems.

    ``resolve_template`` maps an overlay's ``extends`` to the ``(ref, template)`` it found; the ref
    must equal ``extends``. ``scope`` is the team being published to: V17 is asked about it."""
    if not isinstance(text, str):
        raise _refuse(Issue(None, "", f"the document must be text, not {type(text).__name__}"))
    if _bytes(text) > MAX_PUBLISH_BYTES:
        raise _refuse(
            Issue(
                None,
                "",
                f"the document is {_bytes(text)} bytes; the limit is {MAX_PUBLISH_BYTES} bytes",
            )
        )
    clean_prompts = _check_prompts(prompts)
    workflow = _flatten(text, resolve_template)
    issues = [
        *validate_structure(
            workflow,
            manifest=manifest,
            policy=policy,
            sandbox_images=sandbox_images,
            team_config=team_config,
        ),
        *check_gate_dominance(workflow, manifest),
        *check_org_required_gates(workflow, policy, team=scope.team),
    ]
    if issues:
        raise SchemaError(issues, "publish")
    document = _workflow_document(workflow)
    size = _bytes(json.dumps(document))
    if size > MAX_FLATTENED_BYTES:
        raise _refuse(
            Issue(
                None,
                "",
                f"the flattened workflow is {size} bytes; the limit is {MAX_FLATTENED_BYTES} bytes",
            )
        )
    manifest_doc = _manifest_document(manifest)
    stored = _bytes(json.dumps([manifest_doc, clean_prompts]))
    if stored > MAX_MANIFEST_ITEM_BYTES:
        raise _refuse(
            Issue(
                None,
                "prompts",
                f"profiles, effects and prompts are {stored} bytes; "
                f"the limit is {MAX_MANIFEST_ITEM_BYTES} bytes",
            )
        )
    try:  # what is stored must load back to what was validated
        if Workflow.model_validate(document) != workflow:
            raise ValueError("differs")
    except (ValidationError, ValueError):
        raise _refuse(Issue(None, "", "the flattened workflow does not survive storage")) from None
    return Prepared(workflow, document, _bundle_digest(document, manifest_doc, clean_prompts))


# --- storage ---------------------------------------------------------------------------------


def _wf_key(name: str, version: int) -> Key:
    return Key(TEAM_ROOT, f"WF#{name}#{version}")


def _manifest_key(digest: str) -> Key:
    return Key(f"MANIFEST#{digest}", "META")


class Publisher:
    def __init__(
        self,
        store: Store,
        *,
        resolve_template: Resolver,
        sandbox_images: Collection[str] | None = None,
    ) -> None:
        self._store = store
        self._resolve = resolve_template
        self._images = sandbox_images

    def publish(
        self,
        scope: TeamScope,
        *,
        who: Principal,
        text: str,
        manifest: Manifest,
        prompts: Mapping[str, str],
    ) -> Published:
        """Validate and store ``text`` as the next version of its workflow for ``scope``'s team.

        A team admin of that team, or an org admin. The org policy and the team config are read
        now, from the store. Nothing is written unless every check passes."""
        if not (who.is_org_admin or (who.team == scope.team and who.has(TEAM_ADMIN))):
            raise PermissionDeniedError(
                f"{who.actor} may not publish for team {scope.team}: "
                f"it needs {TEAM_ADMIN} in that team or {ORG_ADMIN}"
            )
        policy = OrgPolicyStore(self._store).require()
        prepared = prepare(
            text,
            scope=scope,
            resolve_template=self._resolve,
            manifest=manifest,
            policy=policy,
            prompts=prompts,
            sandbox_images=self._images,
            team_config=TeamConfigStore(self._store).read(scope),
        )
        self._store_manifest(prepared, manifest, prompts)
        name = prepared.workflow.metadata.name
        for _ in range(_ATTEMPTS):
            version = self._next_version(scope, name)
            try:
                self._store.put(
                    scope,
                    _wf_key(name, version),
                    {
                        "name": name,
                        "version": version,
                        "digest": prepared.digest,
                        "published_by": who.actor,
                        "workflow": dict(prepared.document),
                    },
                    when=Absent(),
                )
            except ConditionFailedError:
                continue  # another publish took this number: take the next
            return Published(Pin(scope.team, name, version, prepared.digest), prepared.workflow)
        raise PermanentError(f"could not allocate a version of {name} after {_ATTEMPTS} attempts")

    def latest(self, scope: TeamScope, name: str) -> Pin | None:
        """The newest published version, which new runs pin. ``None`` before the first publish."""
        best = self._latest_item(scope, name)
        if best is None:
            return None
        version, digest = best
        return Pin(scope.team, name, version, digest)

    def _latest_item(self, scope: TeamScope, name: str) -> tuple[int, str] | None:
        best: tuple[int, str] | None = None
        cursor: str | None = None
        prefix = f"WF#{name}#"
        while True:
            page = self._store.query(scope, TEAM_ROOT, sk_prefix=prefix, cursor=cursor)
            for item in page.items:
                tail = item.key.sk[len(prefix) :]
                if tail.isdigit() and (best is None or int(tail) > best[0]):
                    best = (int(tail), str(item.data.get("digest")))
            cursor = page.cursor
            if cursor is None:
                return best

    def _next_version(self, scope: TeamScope, name: str) -> int:
        best = self._latest_item(scope, name)
        return 1 if best is None else best[0] + 1

    def _store_manifest(
        self, prepared: Prepared, manifest: Manifest, prompts: Mapping[str, str]
    ) -> None:
        key = _manifest_key(prepared.digest)
        if self._store.get(PLATFORM, key) is not None:
            return  # content-addressed: the same digest is the same content
        # a concurrent publish of identical content may get there first: that is fine
        with contextlib.suppress(ConditionFailedError):
            self._store.put(
                PLATFORM,
                key,
                {**_manifest_document(manifest), "prompts": dict(prompts)},
                when=Absent(),
            )


def load_pinned(store: Store, scope: TeamScope, pin: Pin) -> Pinned:
    """The workflow, manifest and prompts a run pinned, exactly as published.

    Raises ``PinnedMissingError`` when either item is gone and ``PinnedCorruptError`` when what is
    stored does not hash to ``pin.digest``. A pin from another team finds nothing."""
    if pin.team != scope.team:
        raise PinnedMissingError(f"{pin.name} v{pin.version} is not a version of team {scope.team}")
    item = store.get(scope, _wf_key(pin.name, pin.version))
    if item is None:
        raise PinnedMissingError(f"{pin.name} v{pin.version} is not published for {scope.team}")
    if item.data.get("digest") != pin.digest:
        raise PinnedCorruptError(
            f"{pin.name} v{pin.version} has digest {item.data.get('digest')}, not the pinned digest"
        )
    stored = store.get(PLATFORM, _manifest_key(pin.digest))
    if stored is None:
        raise PinnedMissingError(f"manifest {pin.digest} is not stored")
    data = stored.data
    workflow_doc = item.data.get("workflow")
    prompts = data.get("prompts")
    if (
        not isinstance(workflow_doc, dict)
        or not isinstance(prompts, dict)
        or not isinstance(data.get("profiles"), dict)
        or not isinstance(data.get("effects"), dict)
    ):
        raise PinnedCorruptError(f"the stored records for {pin.digest} are malformed")
    actual = _bundle_digest(workflow_doc, data, prompts)
    if actual != pin.digest:
        raise PinnedCorruptError(
            f"the stored records for {pin.name} v{pin.version} hash to a different digest "
            f"than the pinned {pin.digest}"
        )
    try:
        workflow = Workflow.model_validate(workflow_doc)
        manifest = Manifest.model_validate(
            {"profiles": data["profiles"], "effects": data["effects"]}
        )
    except ValidationError as exc:
        raise PinnedCorruptError(
            f"the stored records for {pin.digest} no longer load: {exc}"
        ) from exc
    return Pinned(workflow, manifest, dict(prompts))
