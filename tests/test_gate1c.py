"""Tests for Gate 1C technology-coherence noise filtering.

Gate 1C flags technology mentions in the report narrative that have no corresponding
CVE detection. Its heuristic (capitalized narrative tokens) is noisy, so it must NOT
flag: terms grounded in the source corpus (actor/victim/country/industry names) or
common action verbs. Only genuinely fabricated product-like terms should surface, and
findings are advisory (non-blocking).
"""

from __future__ import annotations

from src.gates.gate1c_technology_coherence import run
from src.gates.models import GateInput, GateResult


def _run(report: dict, tier1_data: dict | None = None, osint: list | None = None):
    g5 = GateResult(gate_id="5", status="COMPLETE", payload={"report": report})
    gi = GateInput(
        report_type="WEEKLY",
        period_start="2026-05-12",
        period_end="2026-05-19",
        tier1_data=tier1_data or {},
        osint_articles=osint or [],
        prior_results={"5": g5},
    )
    return run(gi, None, "WEEKLY").payload.get("issues", [])


def test_source_grounded_names_are_not_flagged():
    report = {
        "executive_summary": "Qilin ransomware hit Abbott Laboratories across Healthcare in Vietnam.",
        "apt_activity": [{"actor_name": "Qilin", "summary": "Qilin ransomware"}],
        "industry_incidents": [{"organization": "Abbott Laboratories"}],
        "cve_analysis": [{"affected_product": "WordPress"}],
    }
    tier1 = {
        "Intel471": [{"threat_actor": "Qilin", "full_text": "Qilin targeting Vietnam"}],
        "CrowdStrike": [{"target_industries": ["Healthcare"]}],
    }
    osint = [{"title": "Abbott Laboratories breach"}]
    assert _run(report, tier1, osint) == []


def test_common_action_verbs_are_not_flagged():
    report = {
        "executive_summary": "Apply patches. Upgrade systems. Require MFA. Review logs. Monitor traffic.",
        "cve_analysis": [{"affected_product": "WordPress"}],
    }
    assert _run(report) == []


def test_genuinely_fabricated_product_is_flagged():
    report = {
        "executive_summary": "The FooBaz9000 platform is deployed in our environment.",
        "cve_analysis": [{"affected_product": "WordPress"}],
    }
    issues = _run(report)
    assert len(issues) == 1
    assert "Foobaz9000" in issues[0]


def test_qualifying_language_suppresses_flag():
    report = {
        "executive_summary": "FooBaz9000 is an industry threat to monitor, not currently detected in our environment.",
        "cve_analysis": [{"affected_product": "WordPress"}],
    }
    assert _run(report) == []
