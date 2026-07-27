"""Tests for Gate 1D source-attribution advisory checks.

Gate 1D is non-halting: it surfaces `issues`/`warnings` for Gate 6 to fold in. One check
is stat-card `change_pct` sign hygiene — a numeric-looking delta should carry a +/- sign.
Non-comparative markers ("N/A", "New", "Unchanged") have no baseline to sign and must NOT
be flagged (mirrors Gate 1A/1F).
"""

from __future__ import annotations

from src.gates.gate1d_source_attribution import run
from src.gates.models import GateInput, GateResult


def _warnings(stat_cards: list[dict]) -> list[str]:
    report = {"breach_landscape": {"stat_cards": stat_cards}}
    g5 = GateResult(gate_id="5", status="COMPLETE", payload={"report": report})
    gi = GateInput(
        report_type="QUARTERLY",
        period_start="2026-04-01",
        period_end="2026-06-30",
        tier1_data={},
        osint_articles=[],
        prior_results={"5": g5},
    )
    return run(gi, None, "QUARTERLY").payload.get("warnings", [])


def test_na_change_pct_is_not_flagged():
    warnings = _warnings([{"change_pct": "N/A"}, {"change_pct": "n/a"}, {"change_pct": "New"}])
    assert not any("missing +/- sign" in w for w in warnings)


def test_unchanged_and_zero_are_not_flagged():
    warnings = _warnings([{"change_pct": "Unchanged"}, {"change_pct": "0%"}, {"change_pct": None}])
    assert not any("missing +/- sign" in w for w in warnings)


def test_signed_values_are_not_flagged():
    warnings = _warnings([{"change_pct": "+40%"}, {"change_pct": "-12%"}])
    assert not any("missing +/- sign" in w for w in warnings)


def test_unsigned_numeric_value_is_flagged():
    warnings = _warnings([{"change_pct": "40%"}])
    assert any("missing +/- sign" in w and "40%" in w for w in warnings)
