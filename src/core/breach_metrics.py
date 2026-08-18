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

import re
from datetime import date, datetime
from typing import Any

# Org strings that carry no identity — an anonymized/placeholder victim. Distinct anonymized
# breaches must never dedupe into one just because they share a date.
_PLACEHOLDER_ORGS = {
    "", "undisclosed entity", "undisclosed", "unknown", "unnamed", "anonymous", "n/a", "na",
    "redacted", "confidential", "not disclosed", "unspecified",
}

# Trailing legal-entity suffixes stripped when normalizing an org name for dedup, so
# "Acme Health, Inc." and "Acme Health Inc" collide (within and across sources).
_ORG_SUFFIXES = {
    "inc", "llc", "ltd", "plc", "corp", "corporation", "co", "company", "gmbh", "sa", "ag",
    "srl", "spa", "nv", "bv", "lp", "llp", "pllc", "sas", "oy", "ab", "as",
}


def _normalize_org(org: str) -> str:
    """Lowercase, strip punctuation and trailing legal suffixes, collapse whitespace — a
    conservative canonical form so the same named victim dedups across sources."""
    t = re.sub(r"[^a-z0-9 ]+", " ", (org or "").lower())
    words = [w for w in t.split() if w and w not in _ORG_SUFFIXES]
    return " ".join(words)

# Est. Total Impact is estimated per INCIDENT, not per record. A per-record multiplier
# explodes on mega-breaches (a 100M-record dump x $/record yields a nonsense figure,
# because per-record cost drops sharply at scale). IBM "Cost of a Data Breach" also
# publishes an average TOTAL cost per breach, which is stable across breach sizes — that
# is the basis here: sum a per-breach average, weighted by each incident's sector.
DEFAULT_COST_PER_BREACH_USD = 4_880_000.0  # IBM global average total cost per breach

# Minimum dataset incidents before the sector-weighted per-breach average is trusted for the
# enrich-mode rescale. Below this, a handful of incidents (e.g. 3 healthcare rows at ~$9.8M each)
# would set the per-breach average for a much larger live count, so fall back to the flat default.
_MIN_SAMPLE_FOR_SECTOR_AVG = 5

# Approximate average total cost per breach by sector (IBM, recent editions). Healthcare
# runs highest; used to weight a healthcare-heavy peer set instead of a flat average.
SECTOR_COST_PER_BREACH_USD = {
    "Healthcare": 9_770_000.0,
    "Financial": 6_080_000.0,
    "Pharmaceuticals": 5_100_000.0,
    "Technology": 5_000_000.0,
    "Professional/Scientific": 5_000_000.0,
    "Energy": 5_290_000.0,
    "Manufacturing": 4_730_000.0,
    "Public": 2_550_000.0,
}

_RANSOMWARE_MARKERS = ("ransom", "extortion")


def cost_for_sector(sector: str, default: float = DEFAULT_COST_PER_BREACH_USD) -> float:
    """Average total cost per breach for a sector label, falling back to ``default``."""
    return SECTOR_COST_PER_BREACH_USD.get((sector or "").strip(), default)


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
    # Take just the date portion (before any time/space separator) for the date-only formats,
    # instead of the previous fragile `s[:len(fmt)+4]` truncation.
    date_part = re.split(r"[T ]", s, maxsplit=1)[0]
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(date_part, fmt).date()
        except ValueError:
            continue
    # Last resort: fromisoformat handles most ISO shapes (incl. full datetimes).
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
        raw_org = str(rec.get("organization", "")).strip().lower()
        d = _parse_date(rec.get("date"))
        norm_org = _normalize_org(raw_org)
        if raw_org in _PLACEHOLDER_ORGS or not norm_org:
            # Anonymized/placeholder victim carries no identity — never merge distinct ones
            # (they previously collapsed whenever they shared a date, undercounting the quarter).
            key = ("", f"_anon_{len(order)}")
        else:
            key = (norm_org, d.isoformat() if d else "")
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
    default_cost_per_breach_usd: float = DEFAULT_COST_PER_BREACH_USD,
) -> dict[str, Any]:
    """Reduce a set of (already period-scoped) breach records to the stat metrics.

    Est. Total Impact is a PER-INCIDENT estimate: each incident contributes its sector's
    average total breach cost (``cost_for_sector``), falling back to
    ``default_cost_per_breach_usd`` for unknown sectors. This is stable across breach sizes
    — a single mega-breach can't explode the figure the way ``records x $/record`` does.
    ``avg_cost_per_breach_usd`` is exposed so a caller can rescale the estimate to a
    displayed count that differs from the dataset count (dataset lag).

    Records exposed remains a raw sum (no cost applied); ``records_known`` flags whether any
    incident carried a figure. ``notable_examples`` are the largest incidents by records.
    """
    total = len(records)
    ransomware = sum(1 for r in records if _is_ransomware(str(r.get("incident_type", ""))))

    records_total = 0
    records_known = False
    per_breach_costs = []
    for r in records:
        per_breach_costs.append(cost_for_sector(str(r.get("sector", "")), default_cost_per_breach_usd))
        rec_n = r.get("records_exposed")
        # Exclude bool (an int subclass — a stray True would count as 1 record) and negatives
        # (never a valid affected-records figure). 0 is a valid known-zero.
        if isinstance(rec_n, (int, float)) and not isinstance(rec_n, bool) and rec_n >= 0:
            records_total += int(rec_n)
            records_known = True

    est_impact_usd = sum(per_breach_costs)
    # Only trust the sector-weighted per-breach average when the sample is large enough; a tiny
    # dataset falls back to the flat default so the enrich rescale isn't driven by 3 incidents.
    avg_cost_per_breach_usd = (
        est_impact_usd / total if total >= _MIN_SAMPLE_FOR_SECTOR_AVG else default_cost_per_breach_usd
    )

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
        "avg_cost_per_breach_usd": avg_cost_per_breach_usd,
        "records_exposed_millions": round(records_total / 1_000_000, 1),
        "est_impact_millions": round(est_impact_usd / 1_000_000),
        "notable_examples": notable_examples,
    }


def breach_metrics_for_period(
    records: list[dict],
    start: date,
    end: date,
    *,
    default_cost_per_breach_usd: float = DEFAULT_COST_PER_BREACH_USD,
) -> dict[str, Any]:
    """Convenience: dedupe -> bucket to [start, end] -> compute metrics."""
    return compute_breach_metrics(
        scope_breaches(records, start, end), default_cost_per_breach_usd=default_cost_per_breach_usd
    )


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
        if isinstance(rec_n, (int, float)) and not isinstance(rec_n, bool) and rec_n > 0:
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
      - ``"full"``   — dataset is at least as complete as the current count, so counts,
        records and impact all come from the dataset (authoritative). Normal case for
        historical/backfill quarters.
      - ``"enrich"`` — the dataset has FEWER incidents than the live feeds already found
        (dataset lag). Counts are left as-is (a lagging dataset never shrinks the quarter),
        Est. Total Impact is rescaled to the displayed count using the sector-weighted
        per-breach average, and Records Exposed is left untouched (the dataset's records
        would be a partial undercount).

    Est. Total Impact is always ``displayed incident count x sector-weighted per-breach
    average`` — stable across breach sizes. Records Exposed is only filled from a complete
    dataset (full mode) and only when a real figure exists — never fabricated.
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

    # Impact ties to the count actually displayed, so it is always internally consistent
    # (count x per-breach average) whether the count is the dataset's or the live feed's.
    displayed_total = dataset_total if full else int(current_total)
    impact_millions = round(displayed_total * metrics.get("avg_cost_per_breach_usd", 0.0) / 1_000_000)

    values_by_label: dict[str, str] = {"est. total impact": f"${impact_millions}M"}
    if full:
        values_by_label["total incidents"] = str(metrics["total_incidents"])
        values_by_label["ransomware"] = str(metrics["ransomware_count"])
        if metrics.get("records_known"):
            values_by_label["records exposed"] = f"{metrics['records_exposed_millions']}M"

    for card in cards:
        label = str(card.get("label", "")).strip().lower()
        for key, value in values_by_label.items():
            if key in label:
                card["value"] = value
                break
    return "full" if full else "enrich"
