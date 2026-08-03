"""Tests for the Week value type."""

import pytest
from datetime import date

from carryover.week import Week


class TestWeekParsing:
    def test_parse_iso_format(self):
        w = Week.parse("2026-W23")
        assert w.year == 2026
        assert w.week == 23

    def test_parse_report_id(self):
        w = Week.parse("CTI-WK-2026-33")
        assert w.year == 2026
        assert w.week == 33

    def test_parse_invalid_raises(self):
        with pytest.raises(ValueError):
            Week.parse("not-a-week")

    def test_parse_week_zero_raises(self):
        with pytest.raises(ValueError):
            Week.parse("2026-W00")

    def test_parse_week_54_raises(self):
        with pytest.raises(ValueError):
            Week.parse("2026-W54")

    def test_from_date(self):
        # 2026-01-05 is a Monday in ISO week 2 of 2026
        w = Week.from_date(date(2026, 1, 5))
        assert w.year == 2026
        assert w.week == 2

    def test_str_roundtrip(self):
        w = Week(2026, 7)
        assert str(w) == "2026-W07"
        assert Week.parse(str(w)) == w


class TestWeekComparison:
    def test_equal(self):
        assert Week(2026, 23) == Week(2026, 23)

    def test_not_equal(self):
        assert Week(2026, 23) != Week(2026, 24)

    def test_less_than_same_year(self):
        assert Week(2026, 10) < Week(2026, 20)

    def test_less_than_cross_year(self):
        assert Week(2026, 52) < Week(2027, 1)

    def test_greater_than(self):
        assert Week(2026, 30) > Week(2026, 25)

    def test_hash_equal_weeks(self):
        assert hash(Week(2026, 10)) == hash(Week(2026, 10))


class TestWeekArithmetic:
    def test_subtract_same_year(self):
        assert Week(2026, 33) - Week(2026, 23) == 10

    def test_subtract_cross_year_boundary(self):
        # 2026 has 53 ISO weeks. 2026-W49 to 2027-W02:
        # W49→W50→W51→W52→W53→W01→W02 = 6 weeks
        result = Week(2027, 2) - Week(2026, 49)
        assert result == 6

    def test_subtract_full_year(self):
        # 2026 has 53 ISO weeks, so W01 2026 to W01 2027 is 53 weeks.
        result = Week(2027, 1) - Week(2026, 1)
        assert result == 53

    def test_subtract_previous_year_action(self):
        # Action raised in 2025-W50, report for 2026-W03. Age = 5 weeks.
        result = Week(2026, 3) - Week(2025, 50)
        assert result == 5

    def test_addition(self):
        w = Week(2026, 50) + 5
        # 2026 has 53 weeks: W50+5 = W55 wraps to 2027-W02
        assert w.year == 2027
        assert w.week == 2

    def test_subtract_zero(self):
        assert Week(2026, 10) - Week(2026, 10) == 0

    def test_negative_subtraction(self):
        # Earlier minus later gives negative
        result = Week(2026, 10) - Week(2026, 20)
        assert result == -10


class TestWeekEdgeCases:
    def test_week_53_valid_year(self):
        # 2026 has 53 ISO weeks (Thursday, Jan 1 2026 means week 1 starts Dec 29 2025)
        # Actually, 2026 starts on Thursday. Let's check: ISO week 53 exists when
        # the year has 53 weeks. 2026 has 53 weeks.
        w = Week(2026, 53)
        assert w.week == 53

    def test_week_53_invalid_year(self):
        # 2027 does not have 53 ISO weeks
        with pytest.raises(ValueError):
            Week(2027, 53)

    def test_overdue_at_exact_boundary(self):
        # Target is W30, report week is W31 -> overdue
        target = Week(2026, 30)
        report_week = Week(2026, 31)
        assert target < report_week

    def test_not_overdue_at_target_week(self):
        # Target is W30, report week is W30 -> not overdue
        target = Week(2026, 30)
        report_week = Week(2026, 30)
        assert not (target < report_week)
