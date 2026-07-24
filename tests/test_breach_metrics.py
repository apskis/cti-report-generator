"""Tests for src/core/breach_metrics.py — grounded breach stat computation."""

from __future__ import annotations

from datetime import date

from src.core.breach_metrics import (
    apply_metrics_to_stat_cards,
    breach_metrics_for_period,
    bucket_to_period,
    compute_breach_metrics,
    dedupe_breaches,
    filter_records_to_window,
)


def _rec(org, d, itype="Hacking", records=None, source="VCDB"):
    return {"organization": org, "date": d, "incident_type": itype, "records_exposed": records, "source": source}


class TestDedupe:
    def test_dedupe_same_org_and_date_keeps_larger_records(self):
        recs = [
            _rec("Acme", "2026-04-10", records=1000, source="VCDB"),
            _rec("acme", "2026-04-10", records=5000, source="HHS"),  # same incident, bigger figure
            _rec("Beta", "2026-04-11", records=200),
        ]
        out = dedupe_breaches(recs)
        assert len(out) == 2
        acme = next(r for r in out if r["organization"].lower() == "acme")
        assert acme["records_exposed"] == 5000

    def test_undated_unnamed_records_are_kept_distinct(self):
        recs = [_rec("", "", records=1), _rec("", "", records=2)]
        assert len(dedupe_breaches(recs)) == 2


class TestBucket:
    def test_bucket_keeps_only_in_period(self):
        recs = [
            _rec("A", "2026-04-01"),
            _rec("B", "2026-06-30"),
            _rec("C", "2026-03-31"),  # before
            _rec("D", "2026-07-01"),  # after
            _rec("E", ""),  # undated -> excluded (can't place it)
        ]
        out = bucket_to_period(recs, date(2026, 4, 1), date(2026, 6, 30))
        assert sorted(r["organization"] for r in out) == ["A", "B"]

    def test_filter_records_to_window_none_is_passthrough(self):
        recs = [_rec("A", "2026-04-01")]
        assert filter_records_to_window(recs, None) == recs


class TestCompute:
    def test_counts_ransomware_and_records_and_impact(self):
        recs = [
            _rec("A", "2026-04-01", itype="Ransomware", records=1_000_000),
            _rec("B", "2026-04-02", itype="Ransomware & Extortion", records=500_000),
            _rec("C", "2026-04-03", itype="Hacking", records=None),  # records unknown
        ]
        m = compute_breach_metrics(recs, cost_per_record_usd=100.0)
        assert m["total_incidents"] == 3
        assert m["ransomware_count"] == 2
        assert m["records_exposed"] == 1_500_000
        assert m["records_known"] is True
        assert m["est_impact_usd"] == 150_000_000
        assert m["est_impact_millions"] == 150
        assert m["records_exposed_millions"] == 1.5

    def test_no_known_records_flags_records_known_false(self):
        recs = [_rec("A", "2026-04-01", records=None)]
        m = compute_breach_metrics(recs)
        assert m["records_known"] is False
        assert m["records_exposed"] == 0

    def test_for_period_dedupes_then_buckets(self):
        recs = [
            _rec("A", "2026-04-10", records=100, source="VCDB"),
            _rec("a", "2026-04-10", records=100, source="HHS"),  # dup
            _rec("Z", "2026-01-01", records=999),  # out of period
        ]
        m = breach_metrics_for_period(recs, date(2026, 4, 1), date(2026, 6, 30))
        assert m["total_incidents"] == 1


class TestApply:
    def test_apply_overrides_card_values(self):
        analysis = {
            "breach_landscape": {
                "stat_cards": [
                    {"label": "Total Incidents", "value": "N/A"},
                    {"label": "Est. Total Impact", "value": "N/A"},
                    {"label": "Ransomware", "value": "N/A"},
                    {"label": "Records Exposed", "value": "N/A"},
                ]
            }
        }
        metrics = {
            "total_incidents": 12,
            "ransomware_count": 4,
            "records_exposed": 3_000_000,
            "records_known": True,
            "records_exposed_millions": 3.0,
            "est_impact_millions": 495,
        }
        assert apply_metrics_to_stat_cards(analysis, metrics) is True
        cards = {c["label"]: c["value"] for c in analysis["breach_landscape"]["stat_cards"]}
        assert cards["Total Incidents"] == "12"
        assert cards["Ransomware"] == "4"
        assert cards["Records Exposed"] == "3.0M"
        assert cards["Est. Total Impact"] == "$495M"

    def test_apply_noop_when_no_incidents(self):
        analysis = {"breach_landscape": {"stat_cards": [{"label": "Total Incidents", "value": "N/A"}]}}
        assert apply_metrics_to_stat_cards(analysis, {"total_incidents": 0}) is False
        assert analysis["breach_landscape"]["stat_cards"][0]["value"] == "N/A"

    def test_apply_leaves_dollar_cards_when_records_unknown(self):
        analysis = {
            "breach_landscape": {
                "stat_cards": [
                    {"label": "Total Incidents", "value": "N/A"},
                    {"label": "Records Exposed", "value": "N/A"},
                ]
            }
        }
        metrics = {"total_incidents": 5, "ransomware_count": 1, "records_known": False}
        assert apply_metrics_to_stat_cards(analysis, metrics) is True
        cards = {c["label"]: c["value"] for c in analysis["breach_landscape"]["stat_cards"]}
        assert cards["Total Incidents"] == "5"
        assert cards["Records Exposed"] == "N/A"  # untouched — never fabricated
