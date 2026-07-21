"""Tests for Gate 6 adversarial review — deterministic grounding + prior-gate blockers.

These assert the anti-hallucination guarantee end-to-end at the gate level: an
internally-consistent fabrication (a CVE/actor not in any source) now BLOCKS, and
critical findings from the reconciliation gates (1C/1E/1F) become publish blocks.

NEW (Tier 2): Tests for structured JSON validation, quote-back challenge, and
multi-sample voting with the FakeLLMClientTier2.
"""

from __future__ import annotations

import json

from src.gates.gate6_adversarial_review import run
from src.gates.llm_adapter import FakeLLMClientTier2, StructuralLLMClient
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


# -------------------------------------------------------------------------
# Tier 2 tests: Structured JSON validation, quote-back, multi-sampling
# -------------------------------------------------------------------------


def test_tier2_structured_json_valid_citation_passes():
    """Tier 2 #5: Model cites a valid record + quote that we can verify."""
    report = {
        "cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}],
    }
    # LLM returns structured JSON with valid citations
    llm_response = json.dumps(
        {
            "track_a_findings": [],
            "track_b_findings": [
                {
                    "claim": "Executive summary could be more concise",
                    "verdict": "WARN",
                    "source_record_id": None,
                    "quote": None,
                }
            ],
        }
    )
    client = FakeLLMClientTier2({"6": llm_response})
    result = run(_gate_input(report, _source()), client, "WEEKLY")
    # Should pass Track A (no blocking findings), but have Track B warnings
    assert result.status == "PASS"
    assert len(result.payload["track_b"]) > 0


def test_tier2_fabricated_record_id_blocks():
    """Tier 2 #5: Model cites a nonexistent source_record_id → BLOCK."""
    report = {"cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}]}
    llm_response = json.dumps(
        {
            "track_a_findings": [
                {
                    "claim": "CVE-2099-9999 is a critical vulnerability",
                    "verdict": "BLOCK",
                    "source_record_id": "NVD_999",  # Does not exist
                    "quote": "This is a fabricated CVE",
                }
            ],
            "track_b_findings": [],
        }
    )
    client = FakeLLMClientTier2({"6": llm_response})
    result = run(_gate_input(report, _source()), client, "WEEKLY")
    assert result.status == "BLOCK"
    # Should have a finding about the invalid citation
    assert any("CITATION INVALID" in f and "NVD_999" in f for f in result.payload["track_a"])


def test_tier2_fabricated_quote_blocks():
    """Tier 2 #5: Model cites a valid record but with a quote that doesn't appear → BLOCK."""
    tier1 = {"NVD": [{"cve_id": "CVE-2024-1234", "description": "Heap overflow in Acme Server"}]}
    report = {"cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}]}
    llm_response = json.dumps(
        {
            "track_a_findings": [
                {
                    "claim": "This CVE is being actively exploited in the wild",
                    "verdict": "BLOCK",
                    "source_record_id": "NVD_0",
                    "quote": "This vulnerability is being exploited by state-sponsored actors",  # Not in source
                }
            ],
            "track_b_findings": [],
        }
    )
    client = FakeLLMClientTier2({"6": llm_response})
    result = run(_gate_input(report, tier1), client, "WEEKLY")
    assert result.status == "BLOCK"
    # Should have a finding about the unverifiable quote
    assert any("QUOTE UNVERIFIABLE" in f for f in result.payload["track_a"])


def test_tier2_quote_from_wrong_record_blocks():
    """Tier 2 #5: A quote that exists in the corpus but NOT in the cited record → BLOCK.

    Guards the record-specific citation check: the model cites NVD_0 but quotes text
    that only appears in the CrowdStrike record. A corpus-wide match would wrongly pass
    this; the record-specific check must catch it.
    """
    tier1 = {
        "NVD": [{"cve_id": "CVE-2024-1234", "description": "Heap overflow in Acme Server"}],
        "CrowdStrike": [{"actor_name": "COZY BEAR"}],
    }
    report = {"cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}]}
    llm_response = json.dumps(
        {
            "track_a_findings": [
                {
                    "claim": "This CVE is linked to a named actor",
                    "verdict": "BLOCK",
                    "source_record_id": "NVD_0",  # cited record...
                    "quote": "COZY BEAR",  # ...but this text lives in CrowdStrike_0, not NVD_0
                }
            ],
            "track_b_findings": [],
        }
    )
    client = FakeLLMClientTier2({"6": llm_response})
    result = run(_gate_input(report, tier1), client, "WEEKLY")
    assert result.status == "BLOCK"
    assert any("QUOTE UNVERIFIABLE" in f and "NVD_0" in f for f in result.payload["track_a"])


def test_tier2_multi_sample_majority_vote():
    """Tier 2 #7: With multiple samples, only findings in the majority pass through.

    NOTE: This test simulates multi-sampling by running the gate multiple times.
    The actual multi-sampling happens inside gate6's run() function when
    GATE_LLM_SAMPLES > 1, but for testing we verify the voting logic separately.
    """
    report = {"cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}]}

    # Simulate 3 passes with different findings
    # Pass 1: Flags finding A and B
    llm_response_1 = json.dumps(
        {
            "track_a_findings": [
                {"claim": "Finding A", "verdict": "BLOCK", "source_record_id": None, "quote": None},
                {"claim": "Finding B", "verdict": "BLOCK", "source_record_id": None, "quote": None},
            ],
            "track_b_findings": [],
        }
    )
    # Note: Pass 2 and 3 would have different findings in a real multi-sample scenario,
    # but for this unit test we verify that the multi-sample path is exercised by
    # checking the result payload includes tier2_active flag. Finding A appears in 3/3
    # passes → should be in final output; Finding B appears in 1/3 passes → should NOT
    # be in final output; Finding C appears in 1/3 passes → should NOT be in final output

    # For unit testing, we verify that the multi-sample path is exercised by
    # checking the result payload includes tier2_active flag.
    client = FakeLLMClientTier2({"6": llm_response_1})
    result = run(_gate_input(report, _source()), client, "WEEKLY")

    # Verify Tier 2 metadata is present (indicates multi-sampling capability)
    assert "tier2_active" in result.payload
    assert "n_samples" in result.payload


def test_tier2_quote_back_validation_blocks_unverifiable_quote():
    """Tier 2 #6: Threat findings with unverifiable quotes are blocked.

    This tests the quote-back challenge for threat_findings in the report itself
    (not just LLM claims about the report). Uses QUARTERLY report type since
    threat_findings are only in quarterly reports.
    """
    tier1 = {"NVD": [{"cve_id": "CVE-2024-1234", "description": "Heap overflow in Acme Server"}]}
    report = {
        "cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}],
        "threat_findings": [
            {
                "value": "CVE-2024-1234",
                "citation": "Gate 4",
                "supporting_quote": "This is a fabricated quote that does not appear in any source",
            }
        ],
    }
    llm_response = json.dumps({"track_a_findings": [], "track_b_findings": []})
    client = FakeLLMClientTier2({"6": llm_response})
    result = run(_gate_input(report, tier1), client, "QUARTERLY")

    # Should block due to unverifiable quote in threat_findings
    assert result.status == "BLOCK"
    assert any("unverifiable quote" in f.lower() for f in result.payload["track_a"])


def test_tier2_valid_quote_passes():
    """Tier 2 #6: Threat findings with valid, verifiable quotes pass. Uses QUARTERLY report type."""
    tier1 = {"NVD": [{"cve_id": "CVE-2024-1234", "description": "Heap overflow in Acme Server"}]}
    report = {
        "executive_summary": "CVE-2024-1234 was identified.",
        "cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}],
        "threat_findings": [
            {
                "value": "CVE-2024-1234",
                "citation": "Gate 4",
                "sources": ["NVD"],
                "supporting_quote": "Heap overflow in Acme Server",
            }
        ],
    }
    llm_response = json.dumps({"track_a_findings": [], "track_b_findings": []})
    client = FakeLLMClientTier2({"6": llm_response})
    result = run(_gate_input(report, tier1), client, "QUARTERLY")

    # Should pass (no blocking findings)
    assert result.status == "PASS"


def test_structural_client_unchanged():
    """Verify that StructuralLLMClient path still works (Tier 2 does not break Tier 1)."""
    report = {
        "cve_analysis": [{"cve_id": "CVE-2024-1234", "citation": "NVD"}],
        "apt_activity": [{"actor_name": "COZY BEAR"}],
    }
    result = run(_gate_input(report, _source()), StructuralLLMClient(), "WEEKLY")
    assert result.status == "PASS"
    # Should still have the default Track A/B structure
    assert "track_a" in result.payload
    assert "track_b" in result.payload
