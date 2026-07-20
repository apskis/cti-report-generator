"""Tests for escape pattern detection: gate bleed, prose leakage, OSINT promotion, missing clearance marker."""

from __future__ import annotations

import pytest

from src.gates.escape_handler import (
    EscapeDetectedError,
    EscapeType,
    detect_gate_bleed,
    detect_missing_clearance_marker,
    detect_osint_promotion,
    detect_prose_leakage,
    get_recovery_prompt,
)
from src.gates.models import OpenSignal


def test_gate_bleed_catches_two_completion_markers():
    response = "GATE 1 COMPLETE.\n\nGATE 2 COMPLETE. AWAITING CLEARANCE."
    with pytest.raises(EscapeDetectedError) as exc:
        detect_gate_bleed(response, expected_gate_id="1")
    assert exc.value.escape_type == EscapeType.GATE_BLEED


def test_gate_bleed_passes_single_marker():
    response = "| Source | Records |\n|---|---|\n| Intel471 | 5 |\n\nGATE 1 COMPLETE. AWAITING CLEARANCE."
    detect_gate_bleed(response, expected_gate_id="1")


def test_prose_leakage_catches_three_narrative_sentences_in_gate_2():
    response = (
        "The threat landscape continues to evolve rapidly this week.\n"
        "Threat actors have been observed deploying new tactics in recent campaigns.\n"
        "Analysts should review the attached indicators carefully for impact.\n"
        "GATE 2 COMPLETE. AWAITING CLEARANCE."
    )
    with pytest.raises(EscapeDetectedError) as exc:
        detect_prose_leakage(response, gate_id="2")
    assert exc.value.escape_type == EscapeType.PROSE_LEAKAGE


def test_prose_leakage_passes_table_only_gate_2_response():
    response = (
        "| Type | Value | Sources |\n"
        "|---|---|---|\n"
        "| ip | 1.2.3.4 | Intel471 |\n"
        "| domain | evil.com | Intel471 |\n"
        "GATE 2 COMPLETE. AWAITING CLEARANCE."
    )
    detect_prose_leakage(response, gate_id="2")


def test_prose_leakage_ignored_for_gate_5():
    response = (
        "The report draft proceeds with narrative sentences.\n"
        "Each claim ties back to a Gate 4 field.\n"
        "The format permits prose in Gate 5 only.\n"
        "GATE 5 COMPLETE. AWAITING CLEARANCE."
    )
    detect_prose_leakage(response, gate_id="5")


def test_osint_promotion_catches_open_signal_in_threat_findings():
    assembly = {
        "top_iocs": [
            {"value": "EVIL.COM", "sources": []},
        ],
    }
    open_signals = [OpenSignal(article_id="A001", signal_type="ioc", value="EVIL.COM", context_quote="q")]
    with pytest.raises(EscapeDetectedError) as exc:
        detect_osint_promotion(assembly, open_signals)
    assert exc.value.escape_type == EscapeType.OSINT_PROMOTION


def test_osint_promotion_passes_when_value_only_in_open_signals():
    assembly = {
        "top_iocs": [{"value": "1.2.3.4", "sources": ["Intel471"]}],
    }
    open_signals = [OpenSignal(article_id="A001", signal_type="ioc", value="EVIL.COM", context_quote="q")]
    detect_osint_promotion(assembly, open_signals)


def test_missing_clearance_marker_catches_missing_marker():
    response = "| Source | Records |\n| Intel471 | 5 |\n"
    with pytest.raises(EscapeDetectedError):
        detect_missing_clearance_marker(response, gate_id="1")


def test_missing_clearance_marker_passes_with_marker():
    response = "| Source |\nGATE 1 COMPLETE. AWAITING CLEARANCE."
    detect_missing_clearance_marker(response, gate_id="1")


def test_get_recovery_prompt_returns_non_empty_for_all_escape_types():
    for escape_type in EscapeType:
        prompt = get_recovery_prompt(escape_type, gate_id="2", offending_text="example")
        assert prompt
        assert len(prompt) > 20
