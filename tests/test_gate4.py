"""Tests for Gate 4 corroboration matching, OpenSignal generation, OSINT promotion detection."""

from __future__ import annotations

from unittest.mock import patch

from src.gates.gate4_assembly import run
from src.gates.models import (
    IOC,
    ActorLink,
    GateInput,
    GateResult,
    OSINTArticle,
    OSINTSignal,
    SourceRecord,
)


class _FakeLLM:
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return "- Executive Signal: x\n- Top IOCs: y\nGATE 4 COMPLETE. AWAITING CLEARANCE."


def _make_priors(iocs, actor_links, signals, articles):
    return {
        "1": GateResult(
            "1",
            "COMPLETE",
            {
                "tier1_sources": [
                    SourceRecord("Intel471", 1, 1, "a", "b", "OK"),
                    SourceRecord("Intel471", 1, 1, "a", "b", "OK"),
                ]
            },
        ),
        "1B": GateResult(
            "1B",
            "COMPLETE",
            {
                "osint_articles": articles,
                "osint_signals": signals,
                "osint_sources": [
                    SourceRecord("Krebs on Security", 2, 1, "a", "b", "OK", True),
                    SourceRecord("Recorded Future", 2, 0, "a", "b", "[DISABLED IN CONFIG]", False),
                ],
            },
        ),
        "2": GateResult("2", "COMPLETE", {"iocs": iocs}),
        "3": GateResult("3", "COMPLETE", {"actor_links": actor_links}),
    }


def test_corroboration_matches_ioc_present_in_both_tier1_and_osint():
    iocs = [IOC("ip", "1.2.3.4", ["Intel471"], "high", False)]
    links = [ActorLink("1.2.3.4", "BadGroup", "Intel471", "Op", "high", None)]
    articles = [OSINTArticle("A001", "Krebs on Security", "title", "2026-05-15", "http://x")]
    signals = [OSINTSignal("A001", ["1.2.3.4"], [], [], "quote", True)]
    gi = GateInput(
        report_type="WEEKLY",
        period_start="a",
        period_end="b",
        tier1_data={"Intel471": [{"indicator": "1.2.3.4"}]},
        prior_results=_make_priors(iocs, links, signals, articles),
    )
    r = run(gi, _FakeLLM(), "WEEKLY")
    assembly = r.payload["assembly"]
    assert len(assembly["osint_corroboration"]) == 1
    assert assembly["osint_corroboration"][0]["finding"] == "1.2.3.4"
    assert assembly["osint_corroboration"][0]["article_id"] == "A001"


def test_value_only_in_osint_becomes_open_signal_with_label():
    iocs = [IOC("ip", "1.2.3.4", ["Intel471"], "high", False)]
    links = [ActorLink("1.2.3.4", "[UNATTRIBUTED]", "[NONE]", None, None, None)]
    articles = [OSINTArticle("A001", "Krebs on Security", "t", "2026-05-15", "http://x")]
    signals = [OSINTSignal("A001", ["9.9.9.9"], [], ["CVE-2026-99999"], "quote", True)]
    gi = GateInput(
        report_type="WEEKLY",
        period_start="a",
        period_end="b",
        tier1_data={"Intel471": [{"indicator": "1.2.3.4"}]},
        prior_results=_make_priors(iocs, links, signals, articles),
    )
    r = run(gi, _FakeLLM(), "WEEKLY")
    assembly = r.payload["assembly"]
    open_values = {s["value"] for s in assembly["open_signals"]}
    assert "9.9.9.9" in open_values
    assert "CVE-2026-99999" in open_values
    for s in assembly["open_signals"]:
        assert s["label"] == "[OSINT ONLY: NOT VERIFIED BY TIER 1]"


def test_detect_osint_promotion_is_called_during_assembly():
    iocs = [IOC("ip", "1.2.3.4", ["Intel471"], "high", False)]
    links = [ActorLink("1.2.3.4", "[UNATTRIBUTED]", "[NONE]", None, None, None)]
    articles = [OSINTArticle("A001", "Krebs on Security", "t", "2026-05-15", "http://x")]
    signals = [OSINTSignal("A001", ["9.9.9.9"], [], [], "quote", True)]
    gi = GateInput(
        report_type="WEEKLY",
        period_start="a",
        period_end="b",
        tier1_data={"Intel471": [{"indicator": "1.2.3.4"}]},
        prior_results=_make_priors(iocs, links, signals, articles),
    )
    with patch("src.gates.gate4_assembly.detect_osint_promotion") as mock_detect:
        run(gi, _FakeLLM(), "WEEKLY")
        assert mock_detect.called
