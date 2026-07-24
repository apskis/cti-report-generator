"""Explicit reporting-period model for quarterly reports.

The quarterly report used to derive its quarter three different ways (the report
generator from ``today.month`` + a rolling 90-day window, the AI from the data it
saw, and the gap-fill from ``datetime.now()``), so the labels could disagree and
the window bled across calendar quarters. This module makes the period a single,
explicit choice — a calendar quarter with exact start/end dates — that everything
else derives from.

Pure standard library, no I/O, so it is fully unit-testable.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date

# First month of each quarter.
_QUARTER_START_MONTH = {1: 1, 2: 4, 3: 7, 4: 10}


def current_quarter(today: date) -> tuple[int, int]:
    """Return the ``(year, quarter)`` calendar quarter that ``today`` falls in."""
    return today.year, (today.month - 1) // 3 + 1


def previous_quarter(year: int, quarter: int) -> tuple[int, int]:
    """Return the ``(year, quarter)`` of the quarter before the given one."""
    if quarter == 1:
        return year - 1, 4
    return year, quarter - 1


def quarter_bounds(year: int, quarter: int) -> tuple[date, date]:
    """Return the inclusive ``(start_date, end_date)`` of a calendar quarter."""
    if quarter not in (1, 2, 3, 4):
        raise ValueError(f"quarter must be 1-4, got {quarter!r}")
    start_month = _QUARTER_START_MONTH[quarter]
    end_month = start_month + 2
    start = date(year, start_month, 1)
    end = date(year, end_month, calendar.monthrange(year, end_month)[1])
    return start, end


def parse_quarter(value: str | int) -> int:
    """Parse a quarter from ``"Q2"``, ``"q2"``, ``"2"`` or ``2`` into ``1-4``."""
    if isinstance(value, int):
        q = value
    else:
        s = str(value).strip().lower().lstrip("q").strip()
        if not s.isdigit():
            raise ValueError(f"Could not parse quarter from {value!r} (use Q1-Q4 or 1-4)")
        q = int(s)
    if q not in (1, 2, 3, 4):
        raise ValueError(f"quarter must be 1-4, got {q}")
    return q


@dataclass(frozen=True)
class ReportingPeriod:
    """A single calendar quarter with exact bounds and derived labels."""

    year: int
    quarter: int
    start: date
    end: date

    @property
    def label(self) -> str:
        return f"Q{self.quarter} {self.year}"

    @property
    def key(self) -> str:
        """Stable key for history storage, e.g. ``2026-Q2``."""
        return f"{self.year}-Q{self.quarter}"

    @property
    def prior(self) -> ReportingPeriod:
        """The immediately preceding quarter as its own ReportingPeriod."""
        py, pq = previous_quarter(self.year, self.quarter)
        return make_period(py, pq)

    @property
    def next(self) -> ReportingPeriod:
        ny, nq = (self.year + 1, 1) if self.quarter == 4 else (self.year, self.quarter + 1)
        return make_period(ny, nq)

    def contains(self, d: date) -> bool:
        return self.start <= d <= self.end


def make_period(year: int, quarter: int) -> ReportingPeriod:
    """Build a ReportingPeriod for a calendar quarter, validating inputs."""
    quarter = parse_quarter(quarter)
    start, end = quarter_bounds(year, quarter)
    return ReportingPeriod(year=year, quarter=quarter, start=start, end=end)


def resolve_period(year: int | None, quarter: int | str | None, today: date) -> ReportingPeriod:
    """Resolve a reporting period from optional year/quarter, defaulting to the
    calendar quarter that contains ``today`` when either is omitted."""
    cy, cq = current_quarter(today)
    y = int(year) if year else cy
    q = parse_quarter(quarter) if quarter not in (None, "") else cq
    return make_period(y, q)
