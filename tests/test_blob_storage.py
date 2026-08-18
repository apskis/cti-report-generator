"""Tests for create_and_upload_report wiring (esp. quarterly breach-dataset grounding)."""

from __future__ import annotations

from src.reports import blob_storage


class _SpyGenerator:
    """Records the order of set_reporting_period / set_breach_dataset / generate calls."""

    def __init__(self):
        self.calls: list[tuple] = []

    def set_reporting_period(self, period):
        self.calls.append(("period", period))

    def set_breach_dataset(self, records):
        self.calls.append(("dataset", records))

    def generate(self, analysis):
        self.calls.append(("generate", analysis))

    def get_filename(self, **_kwargs):
        return "Q_report.docx"


def _patch(monkeypatch, spy):
    monkeypatch.setattr("src.reports.registry.get_report_generator", lambda rt, **k: spy)
    monkeypatch.setattr(blob_storage, "upload_to_blob", lambda *a, **k: "https://blob/Q_report.docx")


def test_quarterly_wires_breach_dataset_and_period_before_generate(monkeypatch):
    # T1.1 regression: create_and_upload_report must feed the breach dataset + period to the
    # generator BEFORE generate(), so the deployed report grounds its breach stat cards.
    spy = _SpyGenerator()
    _patch(monkeypatch, spy)
    result = blob_storage.create_and_upload_report(
        report_type="quarterly",
        analysis_result={"x": 1},
        storage_account_name="acct",
        storage_account_key="key",
        breach_dataset=[{"organization": "Acme", "date": "2026-05-01"}],
        reporting_period=object(),
    )
    assert result["success"] is True
    names = [c[0] for c in spy.calls]
    assert "period" in names and "dataset" in names
    assert names.index("generate") > names.index("dataset")
    assert names.index("generate") > names.index("period")


def test_weekly_skips_quarterly_setters(monkeypatch):
    # Weekly passes neither breach_dataset nor reporting_period -> only generate() runs.
    spy = _SpyGenerator()
    _patch(monkeypatch, spy)
    result = blob_storage.create_and_upload_report(
        report_type="weekly",
        analysis_result={},
        storage_account_name="a",
        storage_account_key="k",
    )
    assert result["success"] is True
    assert [c[0] for c in spy.calls] == ["generate"]
