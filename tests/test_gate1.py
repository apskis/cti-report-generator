"""Tests for Gate 1 Tier 1 source inventory halt conditions."""

from __future__ import annotations

import pytest

from src.gates.halt import GateHaltError, check_tier1_halt
from src.gates.models import SourceRecord


def _rec(name: str, status: str, enabled: bool = True) -> SourceRecord:
    return SourceRecord(
        source_name=name,
        tier=1,
        records_returned=0 if "GAP" in status else 1,
        period_start="2026-05-12",
        period_end="2026-05-19",
        status=status,
        enabled=enabled,
    )


def test_halt_raises_when_all_tier1_sources_have_gap():
    """check_tier1_halt halts only when EVERY Tier 1 source returned a gap.

    The threshold was intentionally relaxed from "2 or more" to "all" (see the
    docstring on check_tier1_halt): a known transient outage should not halt the
    pipeline as long as at least one Tier 1 source has data.
    """
    records = [
        _rec("NVD", "GAP: timeout"),
        _rec("Intel471", "GAP: 500"),
        _rec("CrowdStrike", "GAP: 503"),
    ]
    with pytest.raises(GateHaltError) as exc:
        check_tier1_halt(records)
    assert exc.value.gate_id == "1"
    assert "Tier 1" in exc.value.reason


def test_halt_passes_when_some_but_not_all_sources_have_gap():
    """Two of three Tier 1 sources failing must NOT halt under the relaxed rule."""
    records = [
        _rec("NVD", "GAP: timeout"),
        _rec("Intel471", "GAP: 500"),
        _rec("CrowdStrike", "OK"),
    ]
    check_tier1_halt(records)


def test_halt_passes_when_only_one_source_has_gap():
    records = [
        _rec("NVD", "GAP: timeout"),
        _rec("Intel471", "OK"),
        _rec("CrowdStrike", "OK"),
    ]
    check_tier1_halt(records)


def test_halt_threshold_is_config_driven(monkeypatch):
    """GATE_TIER1_GAP_HALT_MIN=2 halts at two gapped Tier 1 sources instead of all three."""
    records = [
        _rec("NVD", "GAP: timeout"),
        _rec("Intel471", "GAP: 500"),
        _rec("CrowdStrike", "OK"),
    ]
    # Default ("all"): two gaps must NOT halt.
    check_tier1_halt(records)
    # With threshold 2, the same two gaps halt.
    monkeypatch.setenv("GATE_TIER1_GAP_HALT_MIN", "2")
    with pytest.raises(GateHaltError) as exc:
        check_tier1_halt(records)
    assert exc.value.payload["halt_threshold"] == 2


def test_halt_threshold_explicit_arg_overrides_env():
    records = [_rec("NVD", "GAP: timeout"), _rec("Intel471", "OK"), _rec("CrowdStrike", "OK")]
    with pytest.raises(GateHaltError):
        check_tier1_halt(records, min_gap_to_halt=1)


def test_disabled_source_does_not_trigger_gap_flag():
    """SourceRecord with enabled=False represents Tier 2 disabled OSINT sources.
    Such records should never appear in Tier 1 input, but if they did, they
    must not contribute to the halt count because tier=2.
    """
    records = [
        SourceRecord("NVD", 1, 1, "2026-05-12", "2026-05-19", "OK"),
        SourceRecord("Intel471", 1, 1, "2026-05-12", "2026-05-19", "OK"),
        SourceRecord("CrowdStrike", 1, 1, "2026-05-12", "2026-05-19", "OK"),
        SourceRecord("Recorded Future", 2, 0, "2026-05-12", "2026-05-19", "[DISABLED IN CONFIG]", enabled=False),
    ]
    check_tier1_halt(records)
