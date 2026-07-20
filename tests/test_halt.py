"""Tests for gate halt conditions in gates/halt.py (IOC halt; Tier 1 halt is in test_gate1)."""

from __future__ import annotations

import pytest

from gates.halt import GateHaltError, check_ioc_halt
from gates.models import IOC


def _ioc(value: str = "1.2.3.4", ioc_type: str = "IP") -> IOC:
    return IOC(
        ioc_type=ioc_type,
        value=value,
        sources=["NVD"],
        source_severity="HIGH",
        cross_source_hit=False,
    )


def test_check_ioc_halt_raises_on_empty():
    with pytest.raises(GateHaltError) as exc:
        check_ioc_halt([])
    assert exc.value.gate_id == "2"
    assert exc.value.payload["ioc_count"] == 0


def test_check_ioc_halt_passes_with_at_least_one_ioc():
    # Should not raise.
    check_ioc_halt([_ioc()])
