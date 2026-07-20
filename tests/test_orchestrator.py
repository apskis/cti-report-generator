"""Tests for the gate orchestrator's sequencing, clearance, and halt/escape bookkeeping.

These isolate the orchestrator's control flow by injecting fake gate runners via
``_GATE_RUNNERS`` so the tests do not depend on individual gate internals.
"""

from __future__ import annotations

import pytest

from gates import orchestrator as orch
from gates.escape_handler import EscapeDetectedError, EscapeType
from gates.halt import GateHaltError
from gates.llm_adapter import StructuralLLMClient
from gates.models import GateResult


def _complete_runner(gate_id: str):
    def _runner(gate_input, llm_client, report_type):
        return GateResult(gate_id=gate_id, status="COMPLETE", payload={})

    return _runner


def test_get_gate_sequence_selects_by_report_type():
    assert orch._get_gate_sequence("weekly")[0] == "1"
    assert orch._get_gate_sequence("quarterly")[:3] == ["1", "1A", "1B"]
    # Unknown report types fall back to the weekly sequence.
    assert orch._get_gate_sequence("nonsense") == orch._get_gate_sequence("weekly")


def test_previous_gate_lookup():
    assert orch._previous_gate("1", "weekly") is None
    assert orch._previous_gate("1A", "weekly") == "1"
    assert orch._previous_gate("2", "weekly") == "1B"


def test_run_gate_requires_previous_gate_cleared(monkeypatch):
    monkeypatch.setitem(orch._GATE_RUNNERS, "1", _complete_runner("1"))
    monkeypatch.setitem(orch._GATE_RUNNERS, "1A", _complete_runner("1A"))
    o = orch.GateOrchestrator(StructuralLLMClient(), "weekly")

    o.run_gate("1")
    # 1 is run but not cleared yet -> running 1A must be refused.
    with pytest.raises(RuntimeError, match="previous gate 1 has not been cleared"):
        o.run_gate("1A")

    o.clear("1")
    result = o.run_gate("1A")
    assert result.status == "COMPLETE"
    assert o.current_gate == "1A"


def test_run_gate_records_halt_and_reraises(monkeypatch):
    def _halting(gate_input, llm_client, report_type):
        raise GateHaltError(gate_id="1", reason="boom", payload={"x": 1})

    monkeypatch.setitem(orch._GATE_RUNNERS, "1", _halting)
    o = orch.GateOrchestrator(StructuralLLMClient(), "weekly")

    with pytest.raises(GateHaltError):
        o.run_gate("1")
    assert o.session["1"].status == "HALT"
    assert o.session["1"].halt_reason == "boom"
    assert o.current_gate == "1"


def test_run_gate_records_escape_and_reraises(monkeypatch):
    def _escaping(gate_input, llm_client, report_type):
        raise EscapeDetectedError(EscapeType.GATE_BLEED, "1", "leaked text")

    monkeypatch.setitem(orch._GATE_RUNNERS, "1", _escaping)
    o = orch.GateOrchestrator(StructuralLLMClient(), "weekly")

    with pytest.raises(EscapeDetectedError):
        o.run_gate("1")
    assert o.session["1"].status == "ESCAPE_DETECTED"
    assert o.session["1"].escape_type == EscapeType.GATE_BLEED.value


def test_unknown_gate_id_raises():
    o = orch.GateOrchestrator(StructuralLLMClient(), "weekly")
    with pytest.raises(ValueError, match="Unknown gate id"):
        o.run_gate("99")


def test_clear_rejects_unrun_and_incomplete_gates(monkeypatch):
    def _blocked(gate_input, llm_client, report_type):
        return GateResult(gate_id="1", status="HALT", payload={}, halt_reason="x")

    monkeypatch.setitem(orch._GATE_RUNNERS, "1", _blocked)
    o = orch.GateOrchestrator(StructuralLLMClient(), "weekly")

    with pytest.raises(RuntimeError, match="has not been run"):
        o.clear("1")

    o.run_gate("1")
    with pytest.raises(RuntimeError, match="status is HALT"):
        o.clear("1")


def test_session_summary_shape(monkeypatch):
    monkeypatch.setitem(orch._GATE_RUNNERS, "1", _complete_runner("1"))
    o = orch.GateOrchestrator(StructuralLLMClient(), "weekly")
    o.run_gate("1")
    o.clear("1")
    summary = o.get_session_summary()
    assert summary["current_gate"] == "1"
    assert summary["cleared_gates"] == ["1"]
    assert summary["gate_statuses"] == {"1": "COMPLETE"}
    assert len(summary["clearance_log"]) == 1
