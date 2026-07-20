"""Tests for Gate 1A statistics validation, including resilience to malformed timestamps.

The malformed-timestamp case guards the narrowed exception handling in the data
timestamp-window checks: a bad date on one record must be skipped (logged), not
crash the gate or abort validation.
"""

from __future__ import annotations

import pytest

from src.gates.gate1a_statistics import run
from src.gates.halt import GateHaltError
from src.gates.models import GateInput, GateResult, SourceRecord


def _gate1_prior(records_returned: int = 5, status: str = "OK") -> GateResult:
    src = SourceRecord(
        source_name="NVD",
        tier=1,
        records_returned=records_returned,
        period_start="2026-05-12",
        period_end="2026-05-19",
        status=status,
    )
    return GateResult(gate_id="1", status="COMPLETE", payload={"tier1_sources": [src]})


def _weekly_input(nvd_data, prior_results=None) -> GateInput:
    prior = {"1": _gate1_prior()}
    if prior_results:
        prior.update(prior_results)
    return GateInput(
        report_type="WEEKLY",
        period_start="2026-05-12",
        period_end="2026-05-19",
        tier1_data={"NVD": nvd_data},
        prior_results=prior,
    )


def test_weekly_stats_halts_without_gate1_prior():
    gi = GateInput(report_type="WEEKLY", period_start="2026-05-12", period_end="2026-05-19")
    with pytest.raises(GateHaltError):
        run(gi, llm_client=None, report_type="WEEKLY")


def test_weekly_stats_completes_for_in_window_timestamps():
    gi = _weekly_input([{"cve_id": "CVE-2026-1", "published_date": "2026-05-15T00:00:00Z"}])
    result = run(gi, llm_client=None, report_type="WEEKLY")
    assert result.status == "COMPLETE"
    assert result.gate_id == "1A"


def test_weekly_stats_flags_out_of_window_timestamp():
    gi = _weekly_input([{"cve_id": "CVE-2026-1", "published_date": "2020-01-01T00:00:00Z"}])
    result = run(gi, llm_client=None, report_type="WEEKLY")
    checks = {v["check"]: v for v in result.payload["validations"]}
    assert checks["data_timestamps_within_window"]["passed"] is False


def test_weekly_stats_survives_malformed_timestamp():
    # A malformed published_date must be skipped, not crash the gate.
    gi = _weekly_input([{"cve_id": "CVE-2026-1", "published_date": "not-a-date"}])
    result = run(gi, llm_client=None, report_type="WEEKLY")
    assert result.status == "COMPLETE"
    # The bad record produced no timestamp issue (it was skipped, not flagged).
    checks = {v["check"]: v for v in result.payload["validations"]}
    assert checks["data_timestamps_within_window"]["passed"] is True


def test_unknown_report_type_is_noop_complete():
    gi = GateInput(report_type="MONTHLY", period_start="2026-05-12", period_end="2026-05-19")
    result = run(gi, llm_client=None, report_type="MONTHLY")
    assert result.status == "COMPLETE"
    assert result.payload["validations_run"] == []
