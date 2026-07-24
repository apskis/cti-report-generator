"""Tests for src/core/reporting_period.py — the explicit quarter model."""

from __future__ import annotations

from datetime import date

import pytest

from src.core.reporting_period import (
    current_quarter,
    make_period,
    parse_quarter,
    previous_quarter,
    quarter_bounds,
    resolve_period,
)


class TestQuarterBounds:
    @pytest.mark.parametrize(
        "year,quarter,start,end",
        [
            (2026, 1, date(2026, 1, 1), date(2026, 3, 31)),
            (2026, 2, date(2026, 4, 1), date(2026, 6, 30)),
            (2026, 3, date(2026, 7, 1), date(2026, 9, 30)),
            (2026, 4, date(2026, 10, 1), date(2026, 12, 31)),
            (2024, 1, date(2024, 1, 1), date(2024, 3, 31)),  # leap year Q1 still ends Mar 31
        ],
    )
    def test_bounds(self, year, quarter, start, end):
        assert quarter_bounds(year, quarter) == (start, end)

    def test_invalid_quarter(self):
        with pytest.raises(ValueError):
            quarter_bounds(2026, 5)


class TestParseQuarter:
    @pytest.mark.parametrize("value,expected", [("Q1", 1), ("q2", 2), ("3", 3), (4, 4), (" Q4 ", 4)])
    def test_parse(self, value, expected):
        assert parse_quarter(value) == expected

    @pytest.mark.parametrize("value", ["Q9", "0", "spring", ""])
    def test_bad(self, value):
        with pytest.raises(ValueError):
            parse_quarter(value)


class TestPeriod:
    def test_labels_and_key(self):
        p = make_period(2026, "Q2")
        assert p.label == "Q2 2026"
        assert p.key == "2026-Q2"
        assert p.start == date(2026, 4, 1) and p.end == date(2026, 6, 30)

    def test_prior_within_year(self):
        assert make_period(2026, 2).prior.label == "Q1 2026"

    def test_prior_wraps_year(self):
        p = make_period(2026, 1).prior
        assert p.label == "Q4 2025"
        assert p.start == date(2025, 10, 1) and p.end == date(2025, 12, 31)

    def test_next_wraps_year(self):
        assert make_period(2026, 4).next.label == "Q1 2027"

    def test_contains(self):
        p = make_period(2026, 2)
        assert p.contains(date(2026, 4, 1))
        assert p.contains(date(2026, 6, 30))
        assert not p.contains(date(2026, 3, 31))
        assert not p.contains(date(2026, 7, 1))

    def test_previous_quarter_helper(self):
        assert previous_quarter(2026, 1) == (2025, 4)
        assert previous_quarter(2026, 3) == (2026, 2)


class TestResolveAndCurrent:
    def test_current_quarter(self):
        assert current_quarter(date(2026, 7, 24)) == (2026, 3)
        assert current_quarter(date(2026, 3, 31)) == (2026, 1)

    def test_resolve_defaults_to_current(self):
        p = resolve_period(None, None, date(2026, 7, 24))
        assert p.label == "Q3 2026"

    def test_resolve_explicit(self):
        p = resolve_period(2025, "Q4", date(2026, 7, 24))
        assert p.label == "Q4 2025"
