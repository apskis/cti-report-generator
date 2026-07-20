"""Tests for Gate 6 adversarial review — deterministic grounding + prior-gate blockers.

These assert the anti-hallucination guarantee end-to-end at the gate level: an
internally-consistent fabrication (a CVE/actor not in any source) now BLOCKS, and
critical findings from the reconciliation gates (1C/1E/1F) become publish blocks.
"""

from __future__ import annotations

from src.gates.gate6_adversarial_review import run
from src.gates.llm_adapter import StructuralLLMClient
from src.gates.models import GateInput, GateResult


def _gate_input(report: dict, tier1_data: dict, extra_prior: dict | None = None) -> GateInput:
    prior = {"5": GateResult(gate_id="5", status="COMPLETE", payload={"report": report, "draft_text": ""})}
    prior.update(extra_prior or {})
    return GateInput(
        report_type="WEEKLY",
        period_start="2026-05-12",
        period_end="2026-05-19",
        tier1_data=tier1_data,
        osint_articles=[],
        prior_results=prior,
    )


def _source() -> dict:
    return {"NVD": [{"cve_id": "CVE-2024-1234", "description": "real"}], "CrowdStrike": [{"actor_name": "COZY BEAR"}]}


def test_grounded_report_passes():
    report = {
        "cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}],
        "apt_activity": [{"actor_name": "COZY BEAR"}],
    }
    result = run(_gate_input(report, _source()), StructuralLLMClient(), "WEEKLY")
    assert result.status == "PASS"


def test_fabricated_cve_blocks():
    report = {"cve_analysis": [{"cve_id": "CVE-2099-0000", "citation": "NVD"}]}
    result = run(_gate_input(report, _source()), StructuralLLMClient(), "WEEKLY")
    assert result.status == "BLOCK"
    assert any("CVE-2099-0000" in f for f in result.payload["track_a"])


def test_fabricated_actor_blocks():
    report = {"apt_activity": [{"actor_name": "PHANTOM SERPENT"}]}
    result = run(_gate_input(report, _source()), StructuralLLMClient(), "WEEKLY")
    assert result.status == "BLOCK"
    assert any("PHANTOM SERPENT" in f for f in result.payload["track_a"])


def test_inflated_statistic_blocks():
    report = {
        "apt_activity": [{"actor_name": "COZY BEAR"}],
        "statistics": {"threat_actors": 9},
    }
    result = run(_gate_input(report, _source()), StructuralLLMClient(), "WEEKLY")
    assert result.status == "BLOCK"
    assert any("threat_actors" in f for f in result.payload["track_a"])


def test_prior_gate_1c_issue_blocks():
    report = {"cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}]}
    g1c = GateResult(gate_id="1C", status="COMPLETE", payload={"issues": ["Technology 'Wordpress' not detected"]})
    result = run(_gate_input(report, _source(), {"1C": g1c}), StructuralLLMClient(), "WEEKLY")
    assert result.status == "BLOCK"
    assert any("Gate 1C" in f and "Wordpress" in f for f in result.payload["track_a"])


def test_prior_gate_1f_critical_issue_blocks():
    report = {"cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}]}
    g1f = GateResult(gate_id="1F", status="COMPLETE", payload={"critical_issues": ["❌ generic term used"]})
    result = run(_gate_input(report, _source(), {"1F": g1f}), StructuralLLMClient(), "WEEKLY")
    assert result.status == "BLOCK"
    assert any("Gate 1F" in f for f in result.payload["track_a"])
