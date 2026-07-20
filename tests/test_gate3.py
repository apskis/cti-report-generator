"""Tests for Gate 3 actor and campaign linkage with source-only attribution."""

from __future__ import annotations

from gates.gate3_actor_linkage import run
from gates.models import IOC, GateInput, GateResult, SourceRecord


class _FakeLLM:
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return "| ioc | actor | source |\nGATE 3 COMPLETE. AWAITING CLEARANCE."


def test_unattributed_when_no_source_names_actor():
    iocs = [IOC("ip", "9.9.9.9", ["ThreatQ"], "low", False)]
    g1 = GateResult("1", "COMPLETE", {"tier1_sources": [SourceRecord("ThreatQ", 1, 1, "a", "b", "OK")]})
    g2 = GateResult("2", "COMPLETE", {"iocs": iocs})
    gi = GateInput(
        report_type="WEEKLY",
        period_start="a",
        period_end="b",
        tier1_data={"ThreatQ": [{"indicator": "9.9.9.9"}]},
        prior_results={"1": g1, "2": g2},
    )
    r = run(gi, _FakeLLM(), "WEEKLY")
    links = r.payload["actor_links"]
    assert len(links) == 1
    assert links[0].actor_name == "[UNATTRIBUTED]"


def test_actor_attribution_from_intel471():
    iocs = [IOC("ip", "1.2.3.4", ["Intel471"], "high", False)]
    g1 = GateResult("1", "COMPLETE", {"tier1_sources": [SourceRecord("Intel471", 1, 1, "a", "b", "OK")]})
    g2 = GateResult("2", "COMPLETE", {"iocs": iocs})
    gi = GateInput(
        report_type="WEEKLY",
        period_start="a",
        period_end="b",
        tier1_data={
            "Intel471": [{"indicator": "1.2.3.4", "actor": "BadGroup", "campaign": "OpFoo", "confidence": "high"}]
        },
        prior_results={"1": g1, "2": g2},
    )
    r = run(gi, _FakeLLM(), "WEEKLY")
    link = r.payload["actor_links"][0]
    assert link.actor_name == "BadGroup"
    assert link.attribution_source == "Intel471"
    assert link.campaign == "OpFoo"


def test_region_only_populated_for_quarterly():
    iocs = [IOC("ip", "1.2.3.4", ["Intel471"], "high", False)]
    g1 = GateResult("1", "COMPLETE", {"tier1_sources": [SourceRecord("Intel471", 1, 1, "a", "b", "OK")]})
    g2 = GateResult("2", "COMPLETE", {"iocs": iocs})
    gi = GateInput(
        report_type="QUARTERLY",
        period_start="a",
        period_end="b",
        tier1_data={"Intel471": [{"indicator": "1.2.3.4", "actor": "BadGroup", "region": "RU"}]},
        prior_results={"1": g1, "2": g2},
    )
    r = run(gi, _FakeLLM(), "QUARTERLY")
    assert r.payload["actor_links"][0].region == "RU"

    gi_weekly = GateInput(
        report_type="WEEKLY",
        period_start="a",
        period_end="b",
        tier1_data=gi.tier1_data,
        prior_results={"1": g1, "2": g2},
    )
    r_weekly = run(gi_weekly, _FakeLLM(), "WEEKLY")
    assert r_weekly.payload["actor_links"][0].region is None
