"""Tests for Gate 1B OSINT triage: cap enforcement, disabled sources, ID assignment, signal extraction."""

from __future__ import annotations

from gates.gate1b_osint_triage import run
from gates.models import GateInput


class _FakeLLM:
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return "| A001 | example | t | 2026-05-15 | http://x |\nGATE 1B COMPLETE. AWAITING CLEARANCE."


def _make_article(idx: int, source: str = "Krebs on Security", cves=None) -> dict:
    return {
        "title": f"Article {idx} mentions CVE-2026-12345",
        "url": f"http://example.com/{idx}",
        "summary": "Threat actor used IP 1.2.3.4 to deploy malware",
        "published_date": "2026-05-15",
        "source": source,
        "cves_mentioned": cves if cves is not None else ["CVE-2026-12345"],
    }


def test_article_cap_enforced_and_truncation_noted(tmp_path):
    """The cap comes from `max_total_articles` in the OSINT config. Use an explicit
    config file so the test asserts cap behaviour independently of the shipped
    config value (which has changed over time)."""
    config_file = tmp_path / "osint_sources.yaml"
    config_file.write_text("max_total_articles: 30\nsources: []\n")

    articles = [_make_article(i, source="Krebs on Security") for i in range(25)]
    articles.extend(_make_article(i, source="BleepingComputer") for i in range(10))
    gi = GateInput(
        report_type="WEEKLY",
        period_start="2026-05-12",
        period_end="2026-05-19",
        osint_articles=articles,
        prior_results={"osint_config_path": str(config_file)},
    )
    result = run(gi, _FakeLLM(), "WEEKLY")
    assert result.payload["cap_hit"] is True
    assert len(result.payload["osint_articles"]) == 30
    assert "BleepingComputer" in result.payload["truncated_sources"]


def test_disabled_source_yields_source_record_with_enabled_false():
    gi = GateInput(
        report_type="WEEKLY",
        period_start="2026-05-12",
        period_end="2026-05-19",
        osint_articles=[_make_article(1)],
    )
    result = run(gi, _FakeLLM(), "WEEKLY")
    disabled = [s for s in result.payload["osint_sources"] if not s.enabled]
    assert disabled, "expected at least one disabled source in config"
    for s in disabled:
        assert s.records_returned == 0
        assert "DISABLED" in s.status


def test_article_id_assignment_is_sequential():
    articles = [_make_article(i) for i in range(3)]
    gi = GateInput(
        report_type="WEEKLY",
        period_start="2026-05-12",
        period_end="2026-05-19",
        osint_articles=articles,
    )
    result = run(gi, _FakeLLM(), "WEEKLY")
    ids = [a.article_id for a in result.payload["osint_articles"]]
    assert ids == ["A001", "A002", "A003"]


def test_signal_with_no_iocs_actors_cves_has_no_structured_signals():
    article = {
        "title": "Industry news, no indicators",
        "url": "http://example.com/n",
        "summary": "General discussion of cybersecurity policy.",
        "published_date": "2026-05-15",
        "source": "Dark Reading",
        "cves_mentioned": [],
    }
    gi = GateInput(
        report_type="WEEKLY",
        period_start="2026-05-12",
        period_end="2026-05-19",
        osint_articles=[article],
    )
    result = run(gi, _FakeLLM(), "WEEKLY")
    assert result.payload["osint_signals"][0].has_structured_signals is False
