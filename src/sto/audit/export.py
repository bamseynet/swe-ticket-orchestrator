"""Export by team, run or period, and the verifier for it (PLAN 4.9).

An export carries entries and the signed checkpoints it was given. **A file cannot vouch for its
own completeness**: whoever edits the entries can also drop the newest checkpoint or the runs it
names. So ``verify_export`` takes the trust from the caller: checkpoints fetched from the locked
bucket (``trusted``), or at least the time of the newest checkpoint the caller expects
(``min_checkpoint_at``). A run that no checkpoint names is refused.

What is checked is chosen by the caller, not by the file: the ``team`` (never read from the file),
``from_start``, ``to_tip``, ``all_runs`` and the ``since``/``until`` that was asked for.

**A range that does not start at entry 1 (``from_start=False``) cannot prove where it starts.** Its
anchor is a whole entry, checked for its own hash, run, team and seq, and compared with a
checkpoint only if one has that count. A range with no checkpointed count between its anchor and
its last entry has nothing to compare, so it is refused unless the caller passes
``allow_unchecked_range=True`` and accepts that those entries rest on their own chain alone.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sto.audit.checkpoint import SignedCheckpoint
from sto.audit.errors import AuditVerificationError
from sto.audit.port import StoreAuditLog
from sto.audit.verify import (
    check_against_checkpoints,
    check_checkpoints,
    check_entries,
    team_of,
)
from sto.domain import RunId
from sto.domain.errors import InvalidIdError
from sto.gates.hooks import GENESIS_HASH
from sto.signing.port import Verifier
from sto.store.ports import Scope, Store

FORMAT = "sto.audit.export.v1"


def _window(entries: list[dict[str, Any]], since: int | None, until: int | None) -> tuple[int, int]:
    """``entries[lo:hi]``: one contiguous stretch, from the first entry at or after ``since`` to
    the last one before ``until``. Clocks skew, so ``at`` is not monotonic and a filter would
    leave holes. An empty window sits where it would be: after every entry when ``since`` is
    later than all of them."""
    idx = range(len(entries))
    start = next((i for i in idx if since is None or entries[i]["at"] >= since), len(entries))
    end = next((i for i in reversed(idx) if until is None or entries[i]["at"] < until), None)
    if end is None or start > end:
        return start, start
    return start, end + 1


def export_team(
    store: Store,
    scope: Scope,
    run_ids: Iterable[RunId],
    *,
    checkpoints: Sequence[SignedCheckpoint] = (),
    since: int | None = None,
    until: int | None = None,
) -> dict[str, Any]:
    """A JSON-able document of the runs given and every run a checkpoint names. A run whose
    window does not start at its first entry carries the entry just before it as ``anchor`` (the
    whole entry, so it can be checked), also when the window is empty."""
    log = StoreAuditLog(store)
    names = {str(r) for r in run_ids} | {h.run_id for c in checkpoints for h in c.checkpoint.runs}
    runs: dict[str, Any] = {}
    for run in sorted(names):
        entries = [dict(e) for e in log.entries(scope, RunId.parse(run))]
        lo, hi = _window(entries, since, until)
        runs[run] = {"entries": entries[lo:hi], "anchor": entries[lo - 1] if lo > 0 else None}
    return {
        "format": FORMAT,
        "team": team_of(scope),
        "window": {"since": since, "until": until},
        "runs": runs,
        "checkpoints": [c.to_wire() for c in checkpoints],
    }


def export_json(*args: Any, **kwargs: Any) -> str:
    return json.dumps(export_team(*args, **kwargs), sort_keys=True, indent=2)


def verify_export(
    doc: Mapping[str, Any],
    verifier: Verifier,
    *,
    team: str,
    trusted: Sequence[SignedCheckpoint] = (),
    min_checkpoint_at: int | None = None,
    from_start: bool = True,
    to_tip: bool = True,
    all_runs: bool = True,
    since: int | None = None,
    until: int | None = None,
    allow_unchecked_range: bool = False,
) -> dict[str, int]:
    """Check an export for ``team`` (given by the caller, never taken from the file). Returns
    entries per run; raises ``AuditVerificationError`` (also for a malformed file). The caller
    must give ``trusted`` checkpoints or ``min_checkpoint_at``.

    ``since`` and ``until`` are what the caller asked for: the anchor must lie before ``since``
    and the entries inside the window.

    **``from_start=False`` cannot prove where a range starts.** The anchor is only compared with a
    checkpoint if one has that count, and a range between checkpoints has nothing to compare. So a
    run whose anchor-to-last range holds no checkpointed count is refused, unless the caller
    passes ``allow_unchecked_range=True`` and accepts that those entries rest on nothing but their
    own chain."""
    try:
        return _verify_export(
            doc, verifier, team, trusted, min_checkpoint_at,
            (from_start, to_tip, all_runs), (since, until), allow_unchecked_range,
        )  # fmt: skip
    except AuditVerificationError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, InvalidIdError) as exc:
        raise AuditVerificationError("malformed export") from exc


def _verify_export(
    doc: Mapping[str, Any],
    verifier: Verifier,
    team: str,
    trusted: Sequence[SignedCheckpoint],
    min_checkpoint_at: int | None,
    scope_flags: tuple[bool, bool, bool],
    window: tuple[int | None, int | None],
    allow_unchecked_range: bool,
) -> dict[str, int]:
    from_start, to_tip, all_runs = scope_flags
    since, until = window
    if doc.get("format") != FORMAT:
        raise AuditVerificationError("not an audit export")
    if doc["team"] != team:
        raise AuditVerificationError("the export belongs to another team")
    if not trusted and min_checkpoint_at is None:
        raise AuditVerificationError(
            "the caller must give trusted checkpoints or a minimum checkpoint time"
        )
    checkpoints = [*(SignedCheckpoint.from_wire(w) for w in doc["checkpoints"]), *trusted]
    if not checkpoints:
        raise AuditVerificationError("no checkpoint to verify the export against")
    check_checkpoints(team, checkpoints, verifier)
    newest = max(c.checkpoint.at for c in checkpoints)
    if min_checkpoint_at is not None and newest < min_checkpoint_at:
        raise AuditVerificationError("the newest checkpoint is older than the caller requires")
    named = {h.run_id for c in checkpoints for h in c.checkpoint.runs}
    runs = doc["runs"]
    if not isinstance(runs, Mapping):
        raise AuditVerificationError("malformed export")
    parsed = {str(RunId.parse(k)): v for k, v in runs.items()}  # a bad key never reaches a message
    if len(parsed) != len(runs):
        raise AuditVerificationError("malformed export")
    if parsed.keys() - named:
        raise AuditVerificationError("the export holds a run that no checkpoint names")
    if all_runs and named - parsed.keys():
        raise AuditVerificationError(f"run {sorted(named - parsed.keys())[0]} is not in the export")
    counts: dict[str, int] = {}
    for run, body in parsed.items():
        entries, anchor = body["entries"], body.get("anchor")
        if anchor is None:
            start, hashes = (0, GENESIS_HASH), {}
        else:
            if from_start:
                raise AuditVerificationError(f"run {run} does not start at the beginning")
            a_seq = anchor["seq"]
            if type(a_seq) is not int or a_seq < 1:
                raise AuditVerificationError("malformed export")
            # the anchor is a whole entry: its own hash, run, team and seq are checked
            check_entries([anchor], run, team, anchor=(a_seq - 1, anchor["prev"]))
            start, hashes = (a_seq, anchor["hash"]), {a_seq: anchor["hash"]}
            if since is not None and anchor["at"] >= since:
                raise AuditVerificationError(f"run {run}: the anchor is not before the range")
        walked = check_entries(entries, run, team, anchor=start)
        hashes.update(walked)
        if entries and since is not None and entries[0]["at"] < since:
            raise AuditVerificationError(f"run {run} starts before the range asked for")
        if entries and until is not None and entries[-1]["at"] >= until:
            raise AuditVerificationError(f"run {run} runs past the range asked for")
        last = start[0] + len(entries)
        check_against_checkpoints(run, hashes, last=last, to_tip=to_tip, checkpoints=checkpoints)
        if not allow_unchecked_range and not any(
            start[0] <= h.count <= last
            for c in checkpoints
            for h in c.checkpoint.runs
            if h.run_id == run
        ):
            raise AuditVerificationError(f"no checkpoint count falls in the range of run {run}")
        counts[run] = len(entries)
    return counts
