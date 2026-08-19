"""Tests for the quarter ledger: canonical keys, metrics/basis blocks, and a QoQ round-trip."""

from __future__ import annotations

from src.core import quarter_ledger as ql


class TestCanonicalMetric:
    def test_maps_labels_to_metric_ids(self):
        assert ql.canonical_metric("Total Incidents") == "total_incidents"
        assert ql.canonical_metric("Ransomware") == "ransomware"
        assert ql.canonical_metric("Ransomware Incidents") == "ransomware"  # ransom wins over incident
        assert ql.canonical_metric("Records Exposed") == "records_exposed"
        assert ql.canonical_metric("Est. Total Impact") == "est_impact_usd"
        assert ql.canonical_metric("Something Else") is None
        assert ql.canonical_metric("") is None


class TestMetricsBlock:
    def test_pulls_canonical_numbers_and_rounds_impact(self):
        metrics = {
            "total_incidents": 16,
            "ransomware_count": 7,
            "records_exposed": 1_200_000,
            "est_impact_usd": 48_800_000.4,
        }
        assert ql.metrics_block(metrics) == {
            "total_incidents": 16,
            "ransomware": 7,
            "records_exposed": 1_200_000,
            "est_impact_usd": 48_800_000,
        }

    def test_empty_for_none(self):
        assert ql.metrics_block(None) == {}


class TestPriorValueLookup:
    def test_prefers_label_display_value(self):
        entry = {"breach_stats": {"Total Incidents": "16"}, "metrics": {"total_incidents": 16}}
        assert ql.prior_value_for_label(entry, "Total Incidents") == "16"

    def test_falls_back_to_canonical_metrics_when_relabeled(self):
        # Prior quarter stored the card under a different label -> label miss, canonical hit.
        entry = {"breach_stats": {"Total Breaches": "20"}, "metrics": {"total_incidents": 20}}
        assert ql.prior_value_for_label(entry, "Total Incidents") == 20

    def test_metrics_only_entry_still_yields_prior(self):
        entry = {"metrics": {"ransomware": 5}}
        assert ql.prior_value_for_label(entry, "Ransomware") == 5

    def test_none_when_absent(self):
        assert ql.prior_value_for_label({}, "Total Incidents") is None
        assert ql.prior_value_for_label(None, "Total Incidents") is None


class TestBlobHistoryStore:
    def test_conforms_to_protocol_and_is_non_fatal(self, monkeypatch):
        from src.reports.history_store import BlobQuarterHistoryStore, HistoryStore

        store = BlobQuarterHistoryStore("acct", "key")
        assert isinstance(store, HistoryStore)

        # A storage failure must never abort a report: load -> {}, save -> swallowed.
        def _boom():
            raise RuntimeError("no network")

        monkeypatch.setattr(store, "_blob_client", _boom)
        assert store.load() == {}
        store.save({"2026-Q1": {"metrics": {"total_incidents": 6}}})  # must not raise


class TestQuarterRoundTrip:
    """Quarter N grounds + saves its metrics; quarter N+1 reads them as its prior value."""

    def _analysis(self):
        return {
            "risk_assessment": {"nation_state": "HIGH", "ransomware": "HIGH"},
            "breach_landscape": {
                "stat_cards": [
                    {"label": "Total Incidents", "value": ""},
                    {"label": "Ransomware", "value": ""},
                    {"label": "Est. Total Impact", "value": ""},
                ]
            },
        }

    def _dataset(self, month, n, ransom):
        recs = []
        for i in range(n):
            recs.append({
                "organization": f"Org {month}-{i}",
                "date": f"2026-{month:02d}-15",
                "sector": "Healthcare",
                "incident_type": "Ransomware" if i < ransom else "Hacking",
                "records_exposed": 1000,
            })
        return recs

    def test_prior_quarter_metrics_feed_next_quarter(self, monkeypatch, tmp_path):
        from src.core.reporting_period import make_period
        from src.reports.quarterly_report import QuarterlyReportGenerator

        monkeypatch.setenv("QUARTERLY_HISTORY_DIR", str(tmp_path))

        # Q1 2026: 6 incidents (2 ransomware) -> grounds + saves.
        q1 = QuarterlyReportGenerator()
        q1.set_reporting_period(make_period(2026, 1))
        q1.set_breach_dataset(self._dataset(2, 6, 2))
        q1.generate(self._analysis())

        # The ledger entry carries canonical metrics + basis.
        import json

        history = json.loads((tmp_path / "quarterly_risk_history.json").read_text())
        assert history["2026-Q1"]["metrics"]["total_incidents"] == 6
        assert history["2026-Q1"]["basis"]["mode"] == "full"
        assert history["2026-Q1"]["basis"]["dataset_incidents"] == 6

        # Q2 2026: 10 incidents -> reads Q1 (6) as prior and computes an increase.
        q2 = QuarterlyReportGenerator()
        q2.set_reporting_period(make_period(2026, 2))
        q2.set_breach_dataset(self._dataset(5, 10, 3))
        analysis_q2 = self._analysis()
        q2.generate(analysis_q2)

        total_card = next(
            c for c in analysis_q2["breach_landscape"]["stat_cards"]
            if c["label"] == "Total Incidents"
        )
        assert total_card["value"] == "10"          # grounded to this quarter's dataset
        assert str(total_card["prior_value"]) == "6"  # prior from the Q1 ledger entry
        assert total_card["change_pct"].startswith("+")  # 6 -> 10 is an increase

    def test_round_trip_through_injected_store_not_local_file(self, monkeypatch, tmp_path):
        # Deployed durability: with a history store injected, the ledger round-trips through the
        # store (blob in production) instead of the local file — nothing is written to disk.
        from src.core.reporting_period import make_period
        from src.reports.quarterly_report import QuarterlyReportGenerator

        # Point the local-file dir somewhere empty; assert nothing lands there.
        monkeypatch.setenv("QUARTERLY_HISTORY_DIR", str(tmp_path))

        class _MemStore:
            def __init__(self):
                self.data: dict = {}

            def load(self):
                return dict(self.data)

            def save(self, history):
                self.data = dict(history)

        store = _MemStore()

        q1 = QuarterlyReportGenerator()
        q1.set_history_store(store)
        q1.set_reporting_period(make_period(2026, 1))
        q1.set_breach_dataset(self._dataset(2, 6, 2))
        q1.generate(self._analysis())
        assert store.data.get("2026-Q1", {}).get("metrics", {}).get("total_incidents") == 6
        assert not (tmp_path / "quarterly_risk_history.json").exists()  # not the local file

        q2 = QuarterlyReportGenerator()
        q2.set_history_store(store)
        q2.set_reporting_period(make_period(2026, 2))
        q2.set_breach_dataset(self._dataset(5, 10, 3))
        analysis_q2 = self._analysis()
        q2.generate(analysis_q2)
        total = next(c for c in analysis_q2["breach_landscape"]["stat_cards"] if c["label"] == "Total Incidents")
        assert str(total["prior_value"]) == "6"  # prior read from the injected store
