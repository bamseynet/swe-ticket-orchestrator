"""Business-time maths from a ``TeamConfig`` calendar (D2-12, PLAN 4.4 and 7.1).

Business time is the time inside the team's working window on a working day that is not a
holiday, in the calendar's own time zone. Every window is turned into a pair of UTC instants
first, so a day that holds a daylight-saving change is one hour shorter or longer and the local
clock time of the window never moves. Instants in and out are timezone-aware.

Durations (``Timeouts`` values such as ``90m`` or ``2d``) are business durations: ``s``, ``m`` and
``h`` are business seconds, a ``d`` is one working day's length (closing minus opening) and a
``w`` is a week of them (one per workday in the calendar).

Holidays are passed in as dates; the calendar's ``holidays`` reference is resolved by the caller.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from zoneinfo import ZoneInfo

from sto.config.schema import Calendar, duration_seconds

_WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
# Far more than a 300 day run age needs; a calendar that finds nothing in this many days has none.
_MAX_SCAN_DAYS = 3660


@dataclass(frozen=True)
class BusinessCalendar:
    tz: ZoneInfo
    workdays: frozenset[int]  # 0 = Monday
    opens: dt.time
    closes: dt.time
    holidays: frozenset[dt.date] = frozenset()

    def __post_init__(self) -> None:
        if not self.workdays:
            raise ValueError("a calendar needs at least one workday")
        if self.opens >= self.closes:
            raise ValueError("a working day must end after it starts")

    @classmethod
    def from_config(
        cls, cfg: Calendar, holidays: Iterable[dt.date] | None = None
    ) -> BusinessCalendar:
        """``holidays`` are the dates ``cfg.holidays`` names, resolved by the caller. A config
        that names a holiday list and gets none is refused: treating it as "no holidays" would
        run timers on days the team is off. Pass an empty collection for a list that is empty."""
        if cfg.holidays is not None and holidays is None:
            raise ValueError(
                f"the calendar names holidays ({cfg.holidays!r}) but no dates were passed; "
                "resolve them and pass them in"
            )
        start, end = cfg.hours.split("-")
        return cls(
            ZoneInfo(cfg.timezone),
            frozenset(_WEEKDAYS.index(d) for d in cfg.workdays),
            dt.time.fromisoformat(start),
            dt.time.fromisoformat(end),
            frozenset(holidays or ()),
        )

    # --- windows ----------------------------------------------------------------------------

    def is_workday(self, day: dt.date) -> bool:
        return day.weekday() in self.workdays and day not in self.holidays

    def window(self, day: dt.date) -> tuple[dt.datetime, dt.datetime] | None:
        """The working window of a local date as UTC instants, or ``None`` on a day off."""
        if not self.is_workday(day):
            return None
        return (self._utc(day, self.opens), self._utc(day, self.closes))

    def _utc(self, day: dt.date, at: dt.time) -> dt.datetime:
        # A wall time in a spring-forward gap resolves with the earlier offset; the result is
        # still a valid instant, and the window just loses the missing hour.
        return dt.datetime.combine(day, at, tzinfo=self.tz).astimezone(dt.UTC)

    def _days_from(self, instant: dt.datetime) -> Iterator[dt.date]:
        day = instant.astimezone(self.tz).date()
        for _ in range(_MAX_SCAN_DAYS):
            yield day
            day += dt.timedelta(days=1)

    # --- maths ------------------------------------------------------------------------------

    def add(self, start: dt.datetime, seconds: int) -> dt.datetime:
        """The UTC instant ``seconds`` of business time after ``start``."""
        _aware(start)
        if seconds < 0:
            raise ValueError("business seconds cannot be negative")
        if seconds == 0:
            return start.astimezone(dt.UTC)
        now = start.astimezone(dt.UTC)
        left = seconds
        seen = False
        for day in self._days_from(now):
            win = self.window(day)
            if win is None or win[1] <= now:
                continue
            seen = True
            begin = max(win[0], now)
            room = int((win[1] - begin).total_seconds())
            if left <= room:
                return begin + dt.timedelta(seconds=left)
            left -= room
        if seen:
            raise ValueError(
                f"{seconds} business seconds is more than the next ten years of this calendar "
                "hold; use a shorter duration"
            )
        raise ValueError("the calendar has no business time in the next ten years")

    def business_seconds_between(self, start: dt.datetime, end: dt.datetime) -> int:
        """Business seconds in ``[start, end)``; 0 if ``end`` is not after ``start``."""
        _aware(start)
        _aware(end)
        a, b = start.astimezone(dt.UTC), end.astimezone(dt.UTC)
        if b <= a:
            return 0
        total = 0
        for day in self._days_from(a):
            win = self.window(day)
            if win is not None:
                lo, hi = max(win[0], a), min(win[1], b)
                if hi > lo:
                    total += int((hi - lo).total_seconds())
            if self._utc(day, dt.time(0)) >= b:
                break
        return total

    def add_duration(self, start: dt.datetime, duration: str) -> dt.datetime:
        """``start`` plus a ``Duration`` string counted in business time (see module doc)."""
        return self.add(start, self.duration_seconds(duration))

    def duration_seconds(self, duration: str) -> int:
        n, unit = int(duration[:-1]), duration[-1]
        day = (
            dt.datetime.combine(dt.date(2000, 1, 3), self.closes)
            - dt.datetime.combine(dt.date(2000, 1, 3), self.opens)
        ).seconds
        if unit == "d":
            return n * day
        if unit == "w":
            return n * day * len(self.workdays)
        return duration_seconds(duration)


def _aware(value: dt.datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("an instant needs a timezone")
