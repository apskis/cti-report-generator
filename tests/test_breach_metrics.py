"""Tests for src/core/breach_metrics.py — grounded breach stat computation."""

from __future__ import annotations

from datetime import date

from src.core.breach_metrics import (
    apply_metrics_to_stat_cards,
    breach_metrics_for_period,
    bucket_to_period,
    compute_breach_metrics,
    cost_for_sector,
    dedupe_breaches,
    filter_records_to_window,
    naics_to_sector,
)


def _rec(org, d, itype="Hacking", records=None, source="VCDB", sector=""):
    return {
        "organization": org, "date": d, "incident_type": itype,
        "records_exposed": records, "source": source, "sector": sector,
    }


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

    def test_impact_is_weighted_by_sector(self):
        # 1M healthcare records @ $408 + 1M manufacturing @ $200 = $608M, not a flat rate.
        recs = [
            _rec("Hosp", "2026-04-01", records=1_000_000, sector="Healthcare"),
            _rec("Factory", "2026-04-02", records=1_000_000, sector="Manufacturing"),
        ]
        m = compute_breach_metrics(recs)  # default only used for unknown sectors
        assert m["records_exposed"] == 2_000_000
        assert m["est_impact_usd"] == 1_000_000 * 408 + 1_000_000 * 200
        assert m["est_impact_millions"] == 608

    def test_unknown_sector_uses_default(self):
        recs = [_rec("X", "2026-04-01", records=1_000_000, sector="")]
        m = compute_breach_metrics(recs, cost_per_record_usd=165.0)
        assert m["est_impact_usd"] == 1_000_000 * 165

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


def _metrics(total, ransomware=0, records=0, known=False, rec_m=0.0, imp_m=0):
    return {
        "total_incidents": total,
        "ransomware_count": ransomware,
        "records_exposed": records,
        "records_known": known,
        "records_exposed_millions": rec_m,
        "est_impact_millions": imp_m,
    }


class TestApply:
    def test_apply_full_overrides_card_values(self):
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
        metrics = _metrics(12, ransomware=4, records=3_000_000, known=True, rec_m=3.0, imp_m=495)
        assert apply_metrics_to_stat_cards(analysis, metrics) == "full"
        cards = {c["label"]: c["value"] for c in analysis["breach_landscape"]["stat_cards"]}
        assert cards["Total Incidents"] == "12"
        assert cards["Ransomware"] == "4"
        assert cards["Records Exposed"] == "3.0M"
        assert cards["Est. Total Impact"] == "$495M"

    def test_apply_noop_when_no_incidents(self):
        analysis = {"breach_landscape": {"stat_cards": [{"label": "Total Incidents", "value": "N/A"}]}}
        assert apply_metrics_to_stat_cards(analysis, _metrics(0)) == "none"
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
        assert apply_metrics_to_stat_cards(analysis, _metrics(5, ransomware=1, known=False)) == "full"
        cards = {c["label"]: c["value"] for c in analysis["breach_landscape"]["stat_cards"]}
        assert cards["Total Incidents"] == "5"
        assert cards["Records Exposed"] == "N/A"  # untouched — never fabricated

    # ----- #1: lag-aware grounding -----

    def test_enrich_only_when_dataset_lags_live_count(self):
        # Live feeds already found 20; dataset only has 3 (lag) -> keep counts, fill $/records.
        analysis = {
            "breach_landscape": {
                "stat_cards": [
                    {"label": "Total Incidents", "value": "20"},
                    {"label": "Ransomware", "value": "6"},
                    {"label": "Records Exposed", "value": "N/A"},
                    {"label": "Est. Total Impact", "value": "N/A"},
                ]
            }
        }
        metrics = _metrics(3, ransomware=1, records=2_000_000, known=True, rec_m=2.0, imp_m=330)
        assert apply_metrics_to_stat_cards(analysis, metrics) == "enrich"
        cards = {c["label"]: c["value"] for c in analysis["breach_landscape"]["stat_cards"]}
        assert cards["Total Incidents"] == "20"  # live count preserved, not shrunk to 3
        assert cards["Ransomware"] == "6"  # preserved
        assert cards["Records Exposed"] == "2.0M"  # enriched (live feeds lack this)
        assert cards["Est. Total Impact"] == "$330M"

    def test_full_when_dataset_at_least_as_complete(self):
        analysis = {"breach_landscape": {"stat_cards": [{"label": "Total Incidents", "value": "3"}]}}
        assert apply_metrics_to_stat_cards(analysis, _metrics(9)) == "full"
        assert analysis["breach_landscape"]["stat_cards"][0]["value"] == "9"


class TestSectorMapping:
    def test_naics_to_sector(self):
        assert naics_to_sector("622") == "Healthcare"
        assert naics_to_sector("3254") == "Pharmaceuticals"  # pharma special-cased over mfg
        assert naics_to_sector("339") == "Manufacturing"
        assert naics_to_sector("54171") == "Professional/Scientific"
        assert naics_to_sector("52") == "Financial"
        assert naics_to_sector("") == ""
        assert naics_to_sector("99") == ""

    def test_cost_for_sector_fallback(self):
        assert cost_for_sector("Healthcare") == 408.0
        assert cost_for_sector("Manufacturing") == 200.0
        assert cost_for_sector("", default=165.0) == 165.0
        assert cost_for_sector("Unknownville", default=165.0) == 165.0


class TestIncidentsByType:
    def test_groups_and_names_real_examples(self):
        recs = [
            {"organization": "Covenant Health", "date": "2026-04-01", "incident_type": "Ransomware",
             "records_exposed": 1_200_000},
            {"organization": "Mercy", "date": "2026-04-02", "incident_type": "Ransomware", "records_exposed": 50_000},
            {"organization": "LabCorp", "date": "2026-04-03", "incident_type": "Hacking", "records_exposed": None},
        ]
        from src.core.breach_metrics import build_incidents_by_type

        out = build_incidents_by_type(recs)
        ransom = next(r for r in out if r["type"] == "Ransomware")
        assert ransom["current_count"] == 2
        assert ransom["prior_count"] == "N/A"
        assert "Covenant Health" in ransom["notable_example"]  # largest by records
        assert "1,200,000" in ransom["notable_example"]
        hacking = next(r for r in out if r["type"] == "Hacking")
        assert "LabCorp" in hacking["notable_example"]
