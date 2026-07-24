"""Grounded breach metrics from date-stamped incident datasets.

The quarterly report's breach stat cards (Total Incidents, Ransomware, Records Exposed,
Est. Total Impact) were previously left to the AI, which — correctly — returned N/A for
figures not present in the threat feeds, and produced identical counts across quarters
when the underlying Intel471 alert feed wasn't date-accurate.

This module computes those four metrics deterministically from a *common breach-record
schema* that the dataset collectors (VCDB, HHS, HIBP) all normalize to. Records are
deduplicated across sources, bucketed to the reporting quarter by their real disclosure
date, and reduced to counts + a defensible dollar estimate. Pure standard library, no
I/O, so it is fully unit-testable.

Common record schema (what each collector emits):
    {
        "organization": str,          # victim / breached entity
        "date": "YYYY-MM-DD",         # disclosure or incident date
        "incident_type": str,         # e.g. "Ransomware", "Hacking", "Data Exposure"
        "records_exposed": int | None,# individuals/records affected, if known
        "source": str,                # "VCDB" | "HHS" | "HIBP"
        "summary": str,
        "url": str,
    }
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

# IBM "Cost of a Data Breach" per-record figures are the basis for the ESTIMATED impact.
# The global average is ~$165/record; healthcare (most relevant to a life-sciences customer)
# runs higher (~$400+/record). Kept configurable via CollectorConfig; this is the fallback.
DEFAULT_COST_PER_RECORD_USD = 165.0

_RANSOMWARE_MARKERS = ("ransom", "extortion")


def _parse_date(value: Any) -> date | None:
    """Parse a record's ISO-ish date string into a ``date`` (or ``None``)."""
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if not value:
        return None
    s = str(value).strip().replace("Z", "")
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(s[: len(fmt) + 4], fmt).date()
        except ValueError:
            continue
    # Last resort: fromisoformat handles most ISO shapes.
    try:
        return datetime.fromisoformat(s).date()
    except ValueError:
        return None


def _is_ransomware(incident_type: str) -> bool:
    t = (incident_type or "").lower()
    return any(m in t for m in _RANSOMWARE_MARKERS)


def dedupe_breaches(records: list[dict]) -> list[dict]:
    """Deduplicate incidents across sources by ``(organization, date)``.

    The same breach can appear in more than one dataset. When keys collide, keep the
    record with a known ``records_exposed`` (so a figure isn't lost), preferring the
    larger figure; otherwise keep the first seen.
    """
    best: dict[tuple, dict] = {}
    order: list[tuple] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        org = str(rec.get("organization", "")).strip().lower()
        d = _parse_date(rec.get("date"))
        key = (org, d.isoformat() if d else "")
        if not org and d is None:
            # Undedupable (no identity) — keep as-is under a unique key.
            key = ("", f"_{len(order)}")
        if key not in best:
            best[key] = rec
            order.append(key)
            continue
        # Collision: prefer the record with the larger known records_exposed.
        cur = best[key]
        cur_n = cur.get("records_exposed") or 0
        new_n = rec.get("records_exposed") or 0
        if new_n > cur_n:
            best[key] = rec
    return [best[k] for k in order]


def bucket_to_period(records: list[dict], start: date, end: date) -> list[dict]:
    """Return only records whose disclosure date falls within ``[start, end]``."""
    out = []
    for rec in records:
        d = _parse_date(rec.get("date")) if isinstance(rec, dict) else None
        if d is not None and start <= d <= end:
            out.append(rec)
    return out


def filter_records_to_window(records: list[dict], window: tuple | None) -> list[dict]:
    """When a collection window ``(start, end)`` of datetimes/dates is set, keep only
    records whose date falls inside it; otherwise return records unchanged. Shared by the
    breach-dataset collectors so a historical backfill trims fetched records to the quarter.
    """
    if not window:
        return records
    start, end = window
    start_d = start.date() if isinstance(start, datetime) else start
    end_d = end.date() if isinstance(end, datetime) else end
    return bucket_to_period(records, start_d, end_d)


def compute_breach_metrics(
    records: list[dict],
    *,
    cost_per_record_usd: float = DEFAULT_COST_PER_RECORD_USD,
) -> dict[str, Any]:
    """Reduce a set of (already period-scoped) breach records to the four stat metrics.

    Returns a dict with ``total_incidents``, ``ransomware_count``, ``records_exposed``,
    ``records_known`` (whether any record carried a figure), ``est_impact_usd`` and
    display-ready ``records_exposed_millions`` / ``est_impact_millions`` plus a few
    ``notable_examples`` (largest by records). All values are grounded — no estimation
    beyond the explicit per-record dollar multiplier.
    """
    total = len(records)
    ransomware = sum(1 for r in records if _is_ransomware(str(r.get("incident_type", ""))))
    known = [int(r["records_exposed"]) for r in records if isinstance(r.get("records_exposed"), (int, float))]
    records_total = sum(known)
    records_known = bool(known)
    est_impact_usd = records_total * cost_per_record_usd

    notable = sorted(
        (r for r in records if isinstance(r.get("records_exposed"), (int, float))),
        key=lambda r: r.get("records_exposed", 0),
        reverse=True,
    )[:5]
    notable_examples = [
        {
            "organization": r.get("organization", ""),
            "incident_type": r.get("incident_type", ""),
            "records_exposed": int(r.get("records_exposed", 0)),
        }
        for r in notable
    ]

    return {
        "total_incidents": total,
        "ransomware_count": ransomware,
        "records_exposed": records_total,
        "records_known": records_known,
        "est_impact_usd": est_impact_usd,
        "records_exposed_millions": round(records_total / 1_000_000, 1),
        "est_impact_millions": round(est_impact_usd / 1_000_000),
        "notable_examples": notable_examples,
    }


def breach_metrics_for_period(
    records: list[dict],
    start: date,
    end: date,
    *,
    cost_per_record_usd: float = DEFAULT_COST_PER_RECORD_USD,
) -> dict[str, Any]:
    """Convenience: dedupe -> bucket to [start, end] -> compute metrics."""
    scoped = bucket_to_period(dedupe_breaches(records), start, end)
    return compute_breach_metrics(scoped, cost_per_record_usd=cost_per_record_usd)


def apply_metrics_to_stat_cards(analysis_result: dict, metrics: dict) -> bool:
    """Overwrite the breach stat-card values with grounded dataset metrics.

    Only overrides when the dataset actually had incidents for the period
    (``total_incidents > 0``); otherwise the AI's values (or honest N/A) stand. The
    ``$``/records cards are only filled when at least one record carried a figure — never
    fabricated. Returns True if the cards were grounded.
    """
    breach = analysis_result.get("breach_landscape")
    if not isinstance(breach, dict) or metrics.get("total_incidents", 0) <= 0:
        return False

    records_known = metrics.get("records_known")
    values_by_label = {
        "total incidents": str(metrics["total_incidents"]),
        "ransomware": str(metrics["ransomware_count"]),
    }
    if records_known:
        values_by_label["records exposed"] = f"{metrics['records_exposed_millions']}M"
        values_by_label["est. total impact"] = f"${metrics['est_impact_millions']}M"

    for card in breach.get("stat_cards") or []:
        if not isinstance(card, dict):
            continue
        label = str(card.get("label", "")).strip().lower()
        for key, value in values_by_label.items():
            if key in label:
                card["value"] = value
                break
    return True
