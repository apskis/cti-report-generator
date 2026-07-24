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
# The global average is ~$165/record; some industries run materially higher. Kept
# configurable via CollectorConfig; this is the fallback for records of unknown sector.
DEFAULT_COST_PER_RECORD_USD = 165.0

# Approximate per-record cost by sector (IBM Cost of a Data Breach, recent editions). A
# healthcare-heavy peer set (which an HHS-sourced life-sciences landscape is) would be
# understated by the flat global average, so the dollar estimate is weighted per incident
# using the incident's sector, falling back to the global default when sector is unknown.
SECTOR_COST_PER_RECORD_USD = {
    "Healthcare": 408.0,
    "Financial": 336.0,
    "Pharmaceuticals": 298.0,
    "Technology": 292.0,
    "Professional/Scientific": 288.0,
    "Energy": 262.0,
    "Manufacturing": 200.0,
    "Public": 168.0,
}

_RANSOMWARE_MARKERS = ("ransom", "extortion")


def cost_for_sector(sector: str, default: float = DEFAULT_COST_PER_RECORD_USD) -> float:
    """Per-record cost for a sector label, falling back to ``default`` when unknown."""
    return SECTOR_COST_PER_RECORD_USD.get((sector or "").strip(), default)


def naics_to_sector(naics: Any) -> str:
    """Map a VERIS/NAICS industry code to a coarse sector label (``""`` if unknown)."""
    code = str(naics or "").strip()
    if not code:
        return ""
    if code.startswith("3254"):  # pharmaceutical & medicine manufacturing
        return "Pharmaceuticals"
    two = code[:2]
    return {
        "62": "Healthcare",
        "52": "Financial",
        "54": "Professional/Scientific",
        "51": "Technology",
        "22": "Energy",
        "21": "Energy",
        "31": "Manufacturing",
        "32": "Manufacturing",
        "33": "Manufacturing",
        "92": "Public",
    }.get(two, "")


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
    ``notable_examples`` (largest by records). The dollar estimate is weighted per
    incident by the incident's ``sector`` (see ``SECTOR_COST_PER_RECORD_USD``), falling
    back to ``cost_per_record_usd`` for records of unknown sector — so a healthcare-heavy
    set isn't understated by a flat global rate. No estimation beyond that multiplier.
    """
    total = len(records)
    ransomware = sum(1 for r in records if _is_ransomware(str(r.get("incident_type", ""))))
    records_total = 0
    est_impact_usd = 0.0
    records_known = False
    for r in records:
        rec_n = r.get("records_exposed")
        if not isinstance(rec_n, (int, float)):
            continue
        rec_n = int(rec_n)
        records_total += rec_n
        est_impact_usd += rec_n * cost_for_sector(str(r.get("sector", "")), cost_per_record_usd)
        records_known = True

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
    return compute_breach_metrics(scope_breaches(records, start, end), cost_per_record_usd=cost_per_record_usd)


def scope_breaches(records: list[dict], start: date, end: date) -> list[dict]:
    """Dedupe across sources, then keep only incidents within ``[start, end]``."""
    return bucket_to_period(dedupe_breaches(records), start, end)


def _parse_number(value: Any) -> float | None:
    """Parse a stat value like ``"20"``, ``"1,000"``, ``"$1.2M"`` to a float, else None."""
    if value is None:
        return None
    s = str(value).strip().upper()
    if s in ("", "N/A", "NA", "—", "-"):
        return None
    s = s.replace(",", "").replace("$", "").rstrip("M").strip()
    try:
        return float(s)
    except ValueError:
        return None


def build_incidents_by_type(records: list[dict]) -> list[dict]:
    """Group scoped incidents into an incidents-by-type table with real named examples.

    Each entry: ``{type, current_count, prior_count, notable_example}``. The notable
    example is the largest incident (by records) for that type, using the real
    organization name — never a generic placeholder. ``prior_count`` is left "N/A"
    (the anti-hallucination rule: prior figures come only from stored history).
    """
    groups: dict[str, list[dict]] = {}
    for r in records:
        if not isinstance(r, dict):
            continue
        itype = str(r.get("incident_type", "")).strip() or "Unknown"
        groups.setdefault(itype, []).append(r)

    out = []
    for itype, recs in sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True):
        best = max(recs, key=lambda r: r.get("records_exposed") or 0)
        org = str(best.get("organization", "")).strip() or "Undisclosed entity"
        rec_n = best.get("records_exposed")
        if isinstance(rec_n, (int, float)) and rec_n > 0:
            example = f"{org}: {itype.lower()} affecting {int(rec_n):,} records"
        else:
            example = f"{org}: {itype.lower()} incident"
        out.append(
            {"type": itype, "current_count": len(recs), "prior_count": "N/A", "notable_example": example}
        )
    return out


def apply_metrics_to_stat_cards(analysis_result: dict, metrics: dict) -> str:
    """Ground the breach stat-card values with dataset metrics, lag-aware.

    Returns the grounding mode:
      - ``"none"``   — dataset had no incidents for the period; cards untouched.
      - ``"full"``   — dataset is at least as complete as the current count, so all
        cards (counts + records + impact) come from the dataset (authoritative). This
        is the normal case for historical/backfill quarters.
      - ``"enrich"`` — the dataset has FEWER incidents than the live feeds already found
        (dataset lag), so only the figures the live feeds can't provide (Records Exposed,
        Est. Total Impact) are filled; the incident/ransomware counts are left as-is so a
        lagging dataset never shrinks the current quarter's numbers.

    The ``$``/records cards are only filled when a real records figure exists — never
    fabricated.
    """
    breach = analysis_result.get("breach_landscape")
    if not isinstance(breach, dict) or metrics.get("total_incidents", 0) <= 0:
        return "none"

    cards = [c for c in (breach.get("stat_cards") or []) if isinstance(c, dict)]
    current_total = None
    for card in cards:
        if "total incidents" in str(card.get("label", "")).strip().lower():
            current_total = _parse_number(card.get("value"))
            break

    dataset_total = metrics["total_incidents"]
    # Full when the live feeds gave no count, or the dataset is at least as complete.
    full = current_total is None or dataset_total >= current_total

    values_by_label: dict[str, str] = {}
    if full:
        values_by_label["total incidents"] = str(metrics["total_incidents"])
        values_by_label["ransomware"] = str(metrics["ransomware_count"])
    if metrics.get("records_known"):
        values_by_label["records exposed"] = f"{metrics['records_exposed_millions']}M"
        values_by_label["est. total impact"] = f"${metrics['est_impact_millions']}M"

    for card in cards:
        label = str(card.get("label", "")).strip().lower()
        for key, value in values_by_label.items():
            if key in label:
                card["value"] = value
                break
    return "full" if full else "enrich"
