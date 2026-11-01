"""The audit writer: redact, then chain on the gate service's ``AuditWriter`` seam.

It builds on ``ChainedAuditWriter`` (``sto.gates.hooks``): same body, same hash, same two ops
(the audit entry under ``Absent`` and the head ``RUN#r/CHAIN`` under a version condition). That
is what the effect claim needs (see ``AuditWriter``): the head moves in the transaction of every
gate open and decision, and two writers cannot take the same ``seq``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from sto.audit.redact import redact, redact_text
from sto.gates.hooks import AuditEntry, ChainedAuditWriter, Reader
from sto.store.ports import Op, Scope


class AuditChainWriter:
    def __init__(self) -> None:
        self._chain = ChainedAuditWriter()

    def ops(self, reader: Reader, scope: Scope, entry: AuditEntry) -> Sequence[Op]:
        clean = replace(entry, actor=redact_text(entry.actor), data=redact(entry.data))
        return self._chain.ops(reader, scope, clean)
