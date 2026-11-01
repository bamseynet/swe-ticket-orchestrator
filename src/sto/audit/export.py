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
from dataclasses import dataclass
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
    whole entry, so it can be checked), also when the window is empty. A run that began after the
    window carries its first entry as ``first``, which proves it has nothing in the range."""
    log = StoreAuditLog(store)
    names = {str(r) for r in run_ids} | {h.run_id for c in checkpoints for h in c.checkpoint.runs}
    runs: dict[str, Any] = {}
    for run in sorted(names):
        entries = [dict(e) for e in log.entries(scope, RunId.parse(run))]
        lo, hi = _window(entries, since, until)
        body: dict[str, Any] = {
            "entries": entries[lo:hi],
            "anchor": entries[lo - 1] if lo > 0 else None,
        }
        if lo == hi == 0 and entries:
            body["first"] = entries[0]  # evidence that the run began after the range
        runs[run] = body
    return {
        "format": FORMAT,
        "team": team_of(scope),
        "window": {"since": since, "until": until},
        "runs": runs,
        "checkpoints": [c.to_wire() for c in checkpoints],
    }


def export_json(*args: Any, **kwargs: Any) -> str:
    return json.dumps(export_team(*args, **kwargs), sort_keys=True, indent=2)


@dataclass(frozen=True)
class RunCoverage:
    """What was proved about one run of an export.

    ``compared_through`` is the highest seq whose hash was compared with a signed checkpoint
    (0 if none). **Entries after it in the range rest on the chain alone**: nothing signed covers
    them, so a forged tail past ``compared_through`` is not detectable by this export. ``unchecked``
    means no checkpoint could be compared with the range at all (see ``allow_unchecked_range``)."""

    entries: int
    compared_through: int
    unchecked: bool


@dataclass(frozen=True)
class ExportVerification:
    runs: dict[str, RunCoverage]

    @property
    def counts(self) -> dict[str, int]:
        return {run: c.entries for run, c in self.runs.items()}

    @property
    def unchecked(self) -> tuple[str, ...]:
        return tuple(sorted(run for run, c in self.runs.items() if c.unchecked))


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
) -> ExportVerification:
    """Check an export for ``team`` (given by the caller, never taken from the file). Returns the
    coverage of every run; raises ``AuditVerificationError`` (also for a malformed file). The
    caller must give ``trusted`` checkpoints or ``min_checkpoint_at``.

    ``since`` and ``until`` are what the caller asked for: the anchor must lie before ``since``,
    the entries inside the window, and a run with an empty window needs ``until`` and proof that
    it began after it.

    **A range that does not start at entry 1 (``from_start=False``) cannot prove where it
    starts.** A non-empty range needs a checkpointed count in ``(anchor, last]``; the anchor
    itself is compared but does not count, since an invented range can sit behind a real anchor.
    An empty range needs a checkpoint at its anchor. Entries past ``compared_through`` are
    unprovable (see ``RunCoverage``).

    A run that fails this is refused. With ``allow_unchecked_range=True`` it is accepted and
    listed in ``unchecked`` instead, and **the flag voids ``to_tip`` for that run**: with nothing
    to compare there is no tip to reach, and ``entries`` is all the file claims."""
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
) -> ExportVerification:
    from_start, to_tip, all_runs = scope_flags
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
    out: dict[str, RunCoverage] = {}
    for run, body in parsed.items():
        counts = [h.count for c in checkpoints for h in c.checkpoint.runs if h.run_id == run]
        out[run] = _verify_run_range(
            run,
            body,
            team,
            checkpoints,
            counts,
            (from_start, to_tip),
            window,
            allow_unchecked_range,
        )
    return ExportVerification(out)


def _verify_run_range(
    run: str,
    body: Mapping[str, Any],
    team: str,
    checkpoints: Sequence[SignedCheckpoint],
    counts: list[int],
    flags: tuple[bool, bool],
    window: tuple[int | None, int | None],
    allow_unchecked_range: bool,
) -> RunCoverage:
    from_start, to_tip = flags
    since, until = window
    entries, anchor = body["entries"], body.get("anchor")
    if not isinstance(entries, list):
        raise AuditVerificationError("malformed export")
    if anchor is None:
        start, hashes = (0, GENESIS_HASH), {}
        if not entries:
            return _began_after(run, body, team, checkpoints, counts, to_tip, until)
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
    # something to compare: a count after the anchor (the anchor is not evidence for its own
    # range), or, with no entries, a checkpoint at the anchor
    comparable = (start[0] in counts) if not entries else any(start[0] < c <= last for c in counts)
    # an accepted unchecked run has no tip to reach (the flag voids to_tip); a refused one is
    # still told how far short of its tip it fell, which is the better message
    check_against_checkpoints(
        run, hashes, last=last, to_tip=to_tip and (comparable or not allow_unchecked_range),
        checkpoints=checkpoints,
    )  # fmt: skip
    if not comparable and not allow_unchecked_range:
        raise AuditVerificationError(f"no checkpoint count falls in the range of run {run}")
    through = max((c for c in counts if c in hashes), default=0)
    return RunCoverage(len(entries), through, not comparable)


def _began_after(
    run: str,
    body: Mapping[str, Any],
    team: str,
    checkpoints: Sequence[SignedCheckpoint],
    counts: list[int],
    to_tip: bool,
    until: int | None,
) -> RunCoverage:
    """An empty range with no anchor is only honest if the run began after the range: its first
    entry must be there as evidence, and the caller must have said where the range ends."""
    first = body.get("first")
    if first is None or until is None:
        raise AuditVerificationError(f"run {run} has no entries in the export and shows no reason")
    check_entries([first], run, team)  # seq 1, hash from the genesis, run and team
    if first["at"] < until:
        raise AuditVerificationError(f"run {run} began inside the range but has no entries")
    check_against_checkpoints(
        run, {1: first["hash"]}, last=0, to_tip=to_tip, checkpoints=checkpoints
    )
    return RunCoverage(0, 1 if 1 in counts else 0, False)
