"""Errors of the audit package, in a module of their own so the port can raise them."""

from __future__ import annotations


class AuditVerificationError(ValueError):
    """The audit log or an export does not match its chain or a signed checkpoint, or is not
    well formed. Messages never echo unparsed input."""
