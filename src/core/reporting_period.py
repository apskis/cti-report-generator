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
from datetime import UTC, date, datetime, timedelta

# First month of each quarter.
_QUARTER_START_MONTH = {1: 1, 2: 4, 3: 7, 4: 10}

# Breach reviews are published shortly AFTER the quarter they cover (a "June 2026"
# review lands in mid/late July), so scope the event sources with a trailing grace.
DEFAULT_GRACE_DAYS = 45


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


_RECORD_DATE_KEYS = ("date", "published_date", "published", "last_activity", "created", "reportDate", "updated")


def record_date(rec: dict) -> date | None:
    """Best-effort extraction of a record's date (returns a ``date`` or ``None``)."""
    if not isinstance(rec, dict):
        return None
    for key in _RECORD_DATE_KEYS:
        v = rec.get(key)
        if v is None or v == "":
            continue
        # Epoch seconds or milliseconds (as number or numeric string).
        if isinstance(v, (int, float)) or (isinstance(v, str) and v.strip().isdigit()):
            try:
                ts = float(v)
                if ts > 1e12:  # milliseconds
                    ts /= 1000.0
                return datetime.fromtimestamp(ts, tz=UTC).date()
            except (ValueError, OverflowError, OSError):
                continue
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.strip().replace("Z", "+00:00")).date()
            except ValueError:
                continue
    return None


def filter_sources_to_period(
    data_by_source: dict,
    period: ReportingPeriod,
    *,
    filtered_sources: set[str],
    grace_days: int = DEFAULT_GRACE_DAYS,
) -> tuple[dict, dict]:
    """Scope only ``filtered_sources`` (event/news) to the period; pass others through.

    Pure (no I/O). Returns ``(out, stats)`` where ``stats[source]`` is
    ``{"kept": int, "dropped": int, "out_of_window": bool}``. ``out_of_window`` means the
    source had records but none fell in-window, so it was kept intact (never emptied) to
    avoid gutting the pipeline — the caller should surface this as a warning.

    Reference/IOC sources (e.g. NVD, CrowdStrike) are deliberately NOT filtered: they are
    the "current threat landscape" and always timestamp "now", so quarter-filtering them
    would empty the IOC feed. Undated records are kept. A trailing ``grace_days`` window
    keeps breach reviews published shortly after quarter-end.
    """
    effective_end = period.end + timedelta(days=grace_days)
    out: dict = {}
    stats: dict = {}
    for source, records in data_by_source.items():
        if source not in filtered_sources or not isinstance(records, list):
            out[source] = records
            continue

        kept = []
        dropped = 0
        for rec in records:
            if not isinstance(rec, dict):
                kept.append(rec)
                continue
            d = record_date(rec)
            if d is None or (period.start <= d <= effective_end):
                kept.append(rec)
            else:
                dropped += 1

        if records and not kept:
            out[source] = records  # never empty a source that had data
            stats[source] = {"kept": len(records), "dropped": 0, "out_of_window": True}
            continue

        out[source] = kept
        stats[source] = {"kept": len(kept), "dropped": dropped, "out_of_window": False}
    return out, stats
