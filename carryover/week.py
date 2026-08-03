"""ISO week value type with arithmetic that works across year boundaries."""

from __future__ import annotations

import re
from datetime import date, timedelta
from functools import total_ordering


_WEEK_RE = re.compile(r"^(\d{4})-W(\d{2})$")
_REPORT_ID_RE = re.compile(r"CTI-WK-(\d{4})-(\d{2})")


@total_ordering
class Week:
    """Represents an ISO 8601 week (YYYY-Www).

    Internally stores the Monday of the ISO week as a date, so subtraction
    and comparison work correctly across year boundaries.
    """

    __slots__ = ("_monday",)

    def __init__(self, year: int, week: int):
        if not (1 <= week <= 53):
            raise ValueError(f"Week must be 1–53, got {week}")
        # Compute the Monday of ISO week `week` in `year`.
        # Jan 4 is always in ISO week 1.
        jan4 = date(year, 1, 4)
        # Monday of week 1
        week1_monday = jan4 - timedelta(days=jan4.weekday())
        monday = week1_monday + timedelta(weeks=week - 1)
        # Validate the computed date actually belongs to the requested ISO year/week
        iso_year, iso_week, _ = monday.isocalendar()
        if iso_year != year or iso_week != week:
            raise ValueError(f"{year}-W{week:02d} is not a valid ISO week")
        self._monday = monday

    @classmethod
    def parse(cls, value: str) -> Week:
        """Parse 'YYYY-Www' or 'CTI-WK-YYYY-WW' into a Week."""
        m = _WEEK_RE.match(value)
        if m:
            return cls(int(m.group(1)), int(m.group(2)))
        m = _REPORT_ID_RE.search(value)
        if m:
            return cls(int(m.group(1)), int(m.group(2)))
        raise ValueError(f"Cannot parse week from: {value!r}")

    @classmethod
    def from_date(cls, d: date) -> Week:
        """Return the Week containing the given date."""
        iso_year, iso_week, _ = d.isocalendar()
        return cls(iso_year, iso_week)

    @classmethod
    def current(cls) -> Week:
        """Return the current ISO week."""
        return cls.from_date(date.today())

    @property
    def year(self) -> int:
        return self._monday.isocalendar()[0]

    @property
    def week(self) -> int:
        return self._monday.isocalendar()[1]

    def __repr__(self) -> str:
        return f"Week({self.year}, {self.week})"

    def __str__(self) -> str:
        return f"{self.year}-W{self.week:02d}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Week):
            return NotImplemented
        return self._monday == other._monday

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Week):
            return NotImplemented
        return self._monday < other._monday

    def __hash__(self) -> int:
        return hash(self._monday)

    def __sub__(self, other: Week) -> int:
        """Return the number of weeks between self and other (self - other)."""
        if not isinstance(other, Week):
            return NotImplemented
        delta = (self._monday - other._monday).days
        return delta // 7

    def __add__(self, weeks: int) -> Week:
        """Return a new Week offset by the given number of weeks."""
        new_monday = self._monday + timedelta(weeks=weeks)
        iso_year, iso_week, _ = new_monday.isocalendar()
        return Week(iso_year, iso_week)
