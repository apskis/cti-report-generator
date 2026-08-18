"""Quarter ledger — the durable record of each quarter's grounded breach metrics.

Each quarterly run records its computed, grounded metrics (plus the *basis* they were computed
on) into a per-quarter entry, so the NEXT quarter's report reads a real stored number as its
prior value instead of re-deriving an estimate. Two design points make the ledger robust:

- **Stable metric keys.** The prior lookup keys on a canonical metric id (``total_incidents``,
  ``ransomware``, ``records_exposed``, ``est_impact_usd``) derived from the stat-card label, not
  the label text itself — so an AI that renames "Total Incidents" to "Total Breaches" between
  quarters doesn't silently break the quarter-over-quarter comparison.
- **Recorded basis.** Each entry can carry the grounding ``mode`` and the number of dataset
  incidents behind it, so a large QoQ swing driven by a change in collection basis (e.g. a source
  coming online) can be told apart from a real trend rather than read as one.

This module is pure (no I/O); the report generator owns reading/writing the JSON store and calls
these helpers to build and interpret entries.
"""

from __future__ import annotations

from typing import Any

# Canonical metric ids stored in a ledger entry's ``metrics`` block.
CANONICAL_METRICS = ("total_incidents", "ransomware", "records_exposed", "est_impact_usd")

# Map a stat-card display label to a canonical metric id. Ordered: the first family whose needle
# is a substring of the (lowercased) label wins, so "Ransomware Incidents" -> ransomware before
# the generic "incident" family.
_LABEL_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ransomware", ("ransom",)),
    ("records_exposed", ("record",)),
    ("est_impact_usd", ("impact", "cost")),
    ("total_incidents", ("incident", "breach", "total")),
)


def canonical_metric(label: str) -> str | None:
    """Canonical metric id for a stat-card label, or ``None`` if it maps to none."""
    t = (label or "").strip().lower()
    if not t:
        return None
    for key, needles in _LABEL_FAMILIES:
        if any(n in t for n in needles):
            return key
    return None


def metrics_block(metrics: dict[str, Any] | None) -> dict[str, Any]:
    """Canonical numbers from a ``compute_breach_metrics()`` result (``{}`` if absent).

    Est. impact is stored in whole USD (matching what a "$X.XM" card value parses to), so a prior
    value drawn from here compares like-for-like against a current card value.
    """
    if not metrics:
        return {}
    impact = metrics.get("est_impact_usd")
    return {
        "total_incidents": metrics.get("total_incidents"),
        "ransomware": metrics.get("ransomware_count"),
        "records_exposed": metrics.get("records_exposed"),
        "est_impact_usd": round(impact) if isinstance(impact, (int, float)) else None,
    }


def basis_block(mode: str, dataset_incidents: int, generated_at: str) -> dict[str, Any]:
    """Describe how a quarter's metrics were computed, for QoQ methodology transparency."""
    return {"mode": mode, "dataset_incidents": dataset_incidents, "generated_at": generated_at}


def prior_value_for_label(prior_entry: dict[str, Any] | None, label: str) -> Any:
    """Resilient prior-value lookup for a stat card, or ``None`` if the entry has no value.

    Prefers the label-keyed ``breach_stats`` display value (nice formatting, current behavior),
    then falls back to the canonical ``metrics`` block keyed by the label's metric id — so a
    relabeled or metrics-only (backfilled) entry still yields a prior value.
    """
    if not isinstance(prior_entry, dict):
        return None
    stats = prior_entry.get("breach_stats") or {}
    display = stats.get(str(label).strip())
    if display not in (None, ""):
        return display
    key = canonical_metric(label)
    if key:
        metrics = prior_entry.get("metrics") or {}
        val = metrics.get(key)
        if val is not None:
            return val
    return None
