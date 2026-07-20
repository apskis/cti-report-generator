"""Tests for Gate 2 IOC extraction and zero-IOC halt."""

from __future__ import annotations

import pytest

from src.gates.halt import GateHaltError, check_ioc_halt
from src.gates.models import IOC


def test_zero_ioc_halt_raises():
    with pytest.raises(GateHaltError) as exc:
        check_ioc_halt([])
    assert exc.value.gate_id == "2"


def test_non_empty_ioc_list_passes():
    iocs = [IOC(ioc_type="ip", value="1.2.3.4", sources=["Intel471"], source_severity="high", cross_source_hit=False)]
    check_ioc_halt(iocs)
