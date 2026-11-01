"""Export by team, run or period, and the offline verifier for it (PLAN 4.9).

An export carries entries, chain heads and the signed checkpoints, so an auditor with only the
file and the checkpoint *verifier* (public key or shared key) can check it. A period export
starts at an anchor (the entry before its first one) and is therefore partial: verifying it needs
``require_complete=False``, so a file cannot pass as complete by leaving entries out.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sto.audit.checkpoint import SignedCheckpoint
from sto.audit.port import StoreAuditLog
from sto.audit.verify import (
    AuditVerificationError,
    check_against_checkpoints,
    check_checkpoint_signatures,
    check_entries,
    team_of,
)
from sto.domain import RunId
from sto.gates.hooks import GENESIS_HASH
from sto.signing.port import Verifier
from sto.store.ports import Scope, Store

FORMAT = "sto.audit.export.v1"


def export_team(
    store: Store,
    scope: Scope,
    run_ids: Iterable[RunId],
    *,
    checkpoints: Sequence[SignedCheckpoint] = (),
    since: int | None = None,
    until: int | None = None,
) -> dict[str, Any]:
    """A JSON-able document. ``since`` and ``until`` select entries by ``at`` (``until``
    exclusive); the selection is always one unbroken stretch of the chain."""
    log = StoreAuditLog(store)
    runs: dict[str, Any] = {}
    for run in sorted(
        {str(r) for r in run_ids} | {h.run_id for c in checkpoints for h in c.checkpoint.runs}
    ):
        entries = [dict(e) for e in log.entries(scope, RunId.parse(run))]
        picked = [
            e
            for e in entries
            if (since is None or e["at"] >= since) and (until is None or e["at"] < until)
        ]
        anchor = None
        if picked and picked[0]["seq"] > 1:
            before = entries[picked[0]["seq"] - 2]
            anchor = {"seq": before["seq"], "hash": before["hash"]}
        runs[run] = {"entries": picked, "anchor": anchor}
    return {
        "format": FORMAT,
        "team": team_of(scope),
        "complete": since is None and until is None,
        "runs": runs,
        "checkpoints": [c.to_wire() for c in checkpoints],
    }


def export_json(*args: Any, **kwargs: Any) -> str:
    return json.dumps(export_team(*args, **kwargs), sort_keys=True, indent=2)


def verify_export(
    doc: Mapping[str, Any], verifier: Verifier, *, require_complete: bool = True
) -> dict[str, int]:
    """Check an export on its own. Returns entries per run; raises ``AuditVerificationError``."""
    if doc.get("format") != FORMAT:
        raise AuditVerificationError("not an audit export")
    team = str(doc["team"])
    if require_complete and not doc.get("complete"):
        raise AuditVerificationError("export is partial (a period), not the complete chain")
    checkpoints = [SignedCheckpoint.from_wire(w) for w in doc.get("checkpoints", [])]
    check_checkpoint_signatures(team, checkpoints, verifier)
    if require_complete and not checkpoints:
        raise AuditVerificationError("no checkpoint to verify the export against")
    runs: Mapping[str, Any] = doc["runs"]
    for cp in checkpoints:  # a run a checkpoint names must not be left out of the file
        for head in cp.checkpoint.runs:
            if head.run_id not in runs and require_complete:
                raise AuditVerificationError(f"run {head.run_id} is missing from the export")
    counts: dict[str, int] = {}
    for run, body in runs.items():
        entries = body["entries"]
        anchor = body.get("anchor")
        start = (int(anchor["seq"]), str(anchor["hash"])) if anchor else (0, GENESIS_HASH)
        walked = check_entries(entries, run, team, anchor=start)
        counts[run] = len(entries)
        if require_complete:
            if anchor is not None:
                raise AuditVerificationError(f"run {run} does not start at the beginning")
            count = walked[-1][0] if walked else 0
            check_against_checkpoints(run, dict(walked), count, checkpoints)
    return counts
