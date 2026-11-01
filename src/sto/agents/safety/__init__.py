"""Secret scanning and redaction (D5-04). See ``scanner`` for the seam with prompt rendering."""

from sto.agents.safety.logfilter import SecretScreeningFilter
from sto.agents.safety.patch import (
    MAX_PATCH_CHARS,
    PatchBlockedError,
    PatchFinding,
    check_patch,
    scan_patch,
)
from sto.agents.safety.redact import (
    MAX_ERROR_CHARS,
    NO_ERROR_TEXT,
    REDACTION_FAILED,
    redact_error,
)
from sto.agents.safety.scanner import MAX_SCAN_CHARS, Finding, ScanError, Screened, scan, screen

__all__ = [
    "MAX_ERROR_CHARS",
    "MAX_PATCH_CHARS",
    "MAX_SCAN_CHARS",
    "NO_ERROR_TEXT",
    "REDACTION_FAILED",
    "Finding",
    "PatchBlockedError",
    "PatchFinding",
    "ScanError",
    "Screened",
    "SecretScreeningFilter",
    "check_patch",
    "redact_error",
    "scan",
    "scan_patch",
    "screen",
]
