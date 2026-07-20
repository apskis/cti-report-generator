"""Tests for the deterministic StructuralLLMClient stub used by the automated pipeline."""

from __future__ import annotations

from src.gates.llm_adapter import StructuralLLMClient, _detect_gate_from_prompt


def test_detect_gate_from_prompt():
    assert _detect_gate_from_prompt("Run GATE 1B triage now") == "1B"
    assert _detect_gate_from_prompt("GATE 2 extraction") == "2"
    # No marker -> defaults to gate 1.
    assert _detect_gate_from_prompt("no marker here") == "1"


def test_complete_ends_with_clearance_marker():
    client = StructuralLLMClient()
    out = client.complete("system", "Please run GATE 2 now")
    assert out.strip().endswith("GATE 2 COMPLETE. AWAITING CLEARANCE.")


def test_complete_gate2_returns_table_rows_not_prose():
    client = StructuralLLMClient()
    out = client.complete("system", "GATE 2 extraction")
    # Table pipes present; the body should not read as narrative prose.
    assert "|" in out


def test_complete_gate6_reports_pass():
    client = StructuralLLMClient()
    out = client.complete("system", "GATE 6 adversarial review")
    assert "Overall: PASS" in out
    assert out.strip().endswith("GATE 6 COMPLETE. AWAITING CLEARANCE.")


def test_complete_unknown_gate_defaults_to_gate1_marker():
    client = StructuralLLMClient()
    out = client.complete("system", "no gate marker")
    assert out.strip().endswith("GATE 1 COMPLETE. AWAITING CLEARANCE.")
