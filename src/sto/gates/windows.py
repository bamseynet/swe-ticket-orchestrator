"""Merge windows and UTC clocks for intake (D2-17), kept out of ``sto.engine`` because the engine
modules may not import ``datetime`` (``test_engine_modules_are_pure``). Nothing here reads a
clock: ``now`` is always passed in and must carry a time zone.

``merge_window`` says whether merge may happen now. A deny window, a closed ``allow_only`` cron,
or the sprint's merge freeze holds the run in ``WAITING_EXTERNAL`` until ``until``; the caller
re-evaluates then.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from zoneinfo import ZoneInfo

from sto.config.schema import TeamConfig, duration_seconds
from sto.domain.states import RunStatus

Instant = dt.datetime

__all__ = ["Instant", "MergeWindow", "merge_window", "utc_text"]


def _aware(now: dt.datetime) -> dt.datetime:
    if now.tzinfo is None:
        raise ValueError("the clock needs a timezone")
    return now.astimezone(dt.UTC)


def utc_text(now: dt.datetime) -> str:
    """``now`` in UTC as ISO text (it sorts as time, which the store's indexes rely on)."""
    return _aware(now).isoformat()


@dataclass(frozen=True)
class MergeWindow:
    open: bool
    status: RunStatus  # RUNNING if merge may go ahead, else WAITING_EXTERNAL
    reason: str | None = None
    until: dt.datetime | None = None  # when to look again; None if not known


_OPEN = MergeWindow(True, RunStatus.RUNNING)


def _held(reason: str, until: dt.datetime | None) -> MergeWindow:
    return MergeWindow(False, RunStatus.WAITING_EXTERNAL, reason, until)


class CronError(ValueError):
    pass


_RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


_DIGITS = re.compile(r"[0-9]+")  # ASCII only: str.isdigit() and int() accept ², ١ and the like


def _num(text: str, part: str) -> int:
    if not _DIGITS.fullmatch(text):
        raise CronError(f"{part!r} is not a number")
    return int(text)


def _field(text: str, lo: int, hi: int) -> frozenset[int]:
    out: set[int] = set()
    for part in text.split(","):
        base, slash, step_text = part.partition("/")
        step = _num(step_text, part) if slash else 1
        if step < 1:
            raise CronError(f"step must be at least 1 in {part!r}")
        if base == "*":
            a, b = lo, hi
        elif "-" in base:
            x, _, y = base.partition("-")
            a, b = _num(x, part), _num(y, part)
        else:
            a = _num(base, part)
            b = hi if slash else a
        if not (lo <= a <= b <= hi):
            raise CronError(f"{part!r} is outside {lo}-{hi}, or its range is reversed")
        out.update(range(a, b + 1, step))
    return frozenset(out)


@dataclass(frozen=True)
class _Cron:
    minute: frozenset[int]
    hour: frozenset[int]
    dom: frozenset[int]
    month: frozenset[int]
    dow: frozenset[int]  # 0 = Sunday
    dom_star: bool
    dow_star: bool

    def matches(self, t: dt.datetime) -> bool:
        if t.minute not in self.minute or t.hour not in self.hour or t.month not in self.month:
            return False
        in_dom, in_dow = t.day in self.dom, (t.isoweekday() % 7) in self.dow
        if self.dom_star or self.dow_star:
            return in_dom and in_dow
        return in_dom or in_dow  # both restricted: either, as cron does


def _parse_cron(text: str) -> _Cron:
    parts = text.split()
    if len(parts) != 5:
        raise CronError("a cron has five fields: minute hour day month weekday")
    f = [_field(p, lo, hi) for p, (lo, hi) in zip(parts, _RANGES, strict=True)]
    return _Cron(
        f[0], f[1], f[2], f[3], frozenset(d % 7 for d in f[4]), parts[2] == "*", parts[4] == "*"
    )


_CRON_SCAN_DAYS = 400


def _local(t: dt.datetime, tz: ZoneInfo | dt.tzinfo) -> dt.datetime:
    return t.astimezone(tz)


def _next_match(cron: _Cron, after: dt.datetime, tz: ZoneInfo | dt.tzinfo) -> dt.datetime | None:
    """The first matching minute strictly after ``after`` (UTC), scanning local days. A local time
    that does not exist (the hour skipped in spring) is not a match; a repeated autumn hour is
    matched at its first pass."""
    start = _local(after, tz)
    hours, minutes = sorted(cron.hour), sorted(cron.minute)
    for offset in range(_CRON_SCAN_DAYS):
        day = start.date() + dt.timedelta(days=offset)
        for h in hours:
            for m in minutes:
                local = dt.datetime.combine(day, dt.time(h, m), tzinfo=tz)
                utc = local.astimezone(dt.UTC)
                if utc > after and cron.matches(_local(utc, tz)):
                    return utc
    return None


def _cron_window(text: str, now: dt.datetime, tz: ZoneInfo | dt.tzinfo) -> MergeWindow | None:
    try:
        cron = _parse_cron(text)
    except ValueError as exc:  # CronError, and anything else a bad cron could raise
        return _held(f"change_windows.allow_only is not a valid cron ({exc}); merge is held", None)
    if cron.matches(_local(now, tz)):  # the cron has minute resolution: seconds never matter
        return None
    return _held("outside change_windows.allow_only", _next_match(cron, now, tz))


def _sprint_window(
    cfg: TeamConfig, now: dt.datetime, tz: ZoneInfo | dt.tzinfo
) -> MergeWindow | None:
    """The sprint is whole local dates in the team zone, so a daylight-saving change inside it
    moves neither the day it ends on nor the local midnight it ends at. The freeze starts a
    whole-day (``d``, ``w``) or absolute (``s``, ``m``, ``h``) duration before that midnight."""
    sprint = cfg.sprint
    freeze = None if sprint is None else sprint.merge_freeze_before_end
    if sprint is None or freeze is None:
        return None
    today = now.astimezone(tz).date()
    if today < sprint.anchor:
        return None
    length = 7 * int(sprint.cadence[0])
    end_date = sprint.anchor + dt.timedelta(
        days=((today - sprint.anchor).days // length + 1) * length
    )
    end_local = dt.datetime.combine(end_date, dt.time(), tzinfo=tz)
    end = end_local.astimezone(dt.UTC)
    span = dt.timedelta(seconds=duration_seconds(freeze))
    # same-zone arithmetic on an aware datetime is wall-clock: a "1d" freeze starts at the local
    # midnight a calendar day earlier, even if that day is 23 or 25 hours long
    start = (end_local - span if freeze[-1] in "dw" else end - span).astimezone(dt.UTC)
    return _held("sprint merge freeze", end) if now >= start else None


def merge_window(cfg: TeamConfig, now: dt.datetime) -> MergeWindow:
    """May merge happen at ``now``? Deny windows, ``allow_only`` and the sprint freeze each hold
    it; the answer with the latest known reopening wins, and an unknown reopening wins over all.
    Local time (the cron, the sprint's day boundaries) is in the team calendar's zone, or UTC."""
    now = _aware(now)
    tz: ZoneInfo | dt.tzinfo = ZoneInfo(cfg.calendar.timezone) if cfg.calendar else dt.UTC
    holds: list[MergeWindow] = []
    windows = cfg.change_windows
    if windows is not None:
        for deny in windows.deny:
            if deny.from_ <= now < deny.to:
                holds.append(_held(f"change window: {deny.reason}", deny.to))
        if windows.allow_only is not None and (w := _cron_window(windows.allow_only, now, tz)):
            holds.append(w)
    if w := _sprint_window(cfg, now, tz):
        holds.append(w)
    if not holds:
        return _OPEN
    unknown = [h for h in holds if h.until is None]
    pick = unknown[0] if unknown else max(holds, key=lambda h: h.until or now)
    reasons = "; ".join(dict.fromkeys(h.reason or "" for h in holds))
    return _held(reasons, pick.until)
