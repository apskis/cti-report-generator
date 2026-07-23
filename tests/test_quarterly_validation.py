"""Tests for src/validation/quarterly_validation.py.

Focus: Q12 — notable_example victims are grounded against the collected source
data, so a specific, plausible, but ABSENT company is flagged (the generic-term
blocklist can never catch that failure mode).
"""

from __future__ import annotations

from src.validation.quarterly_validation import QuarterlyReportValidator


def _report_with_victim(notable_example: str) -> dict:
    return {
        "executive_summary": "A three paragraph strategic brief.\n\nPara two.\n\nPara three.",
        "breach_landscape": {
            "incidents_by_type": [
                {"type": "Ransomware", "current_count": "5", "notable_example": notable_example}
            ]
        },
    }


class TestNotableExampleGrounding:
    def test_grounded_victim_produces_no_grounding_warning(self):
        v = QuarterlyReportValidator()
        source = "Covenant Health reported a ransomware attack this quarter."
        v.validate(_report_with_victim("Covenant Health: 3-week outage"), source_text=source)
        assert not any("does not appear in any collected source" in w for w in v.warnings)

    def test_absent_victim_is_flagged(self):
        v = QuarterlyReportValidator()
        source = "Covenant Health reported a ransomware attack this quarter."
        v.validate(_report_with_victim("Regeneron: ransomware exposed 2M records"), source_text=source)
        assert any("Regeneron" in w and "does not appear" in w for w in v.warnings)

    def test_no_source_text_skips_grounding_check(self):
        v = QuarterlyReportValidator()
        # Without source_text we cannot ground; absence of a grounding warning is expected.
        v.validate(_report_with_victim("Regeneron: ransomware exposed 2M records"))
        assert not any("does not appear" in w for w in v.warnings)

    def test_extract_victim_handles_colon_and_hyphen(self):
        assert QuarterlyReportValidator._extract_victim("Acme Corp: breach") == "Acme Corp"
        assert QuarterlyReportValidator._extract_victim("Acme Corp - breach") == "Acme Corp"
        assert QuarterlyReportValidator._extract_victim("Acme (a biotech firm): breach") == "Acme"
        assert QuarterlyReportValidator._extract_victim("no separator here") == ""
