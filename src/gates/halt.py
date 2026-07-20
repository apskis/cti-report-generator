"""Halt conditions enforced at gate boundaries.

A halt is a structural failure that requires analyst decision before the
pipeline can proceed. Halts are distinct from escapes: a halt is a property
of the source data (e.g. two Tier 1 sources returned errors), while an escape
is a property of the model output (e.g. the model leaked training knowledge).
"""

from __future__ import annotations

import logging
import os

from .models import IOC, SourceRecord

logger = logging.getLogger(__name__)

# Env var controlling how many gapped Tier 1 sources trigger a halt. Accepts:
#   "all"  (default) - halt only when EVERY Tier 1 source gapped
#   an int N         - halt when N or more Tier 1 sources gapped (clamped to [1, total])
# Making this explicit fixes the previously-silent drift from the documented "2+" rule
# to "all"; the threshold is now a deliberate, visible configuration choice.
_TIER1_HALT_ENV = "GATE_TIER1_GAP_HALT_MIN"


class GateHaltError(Exception):
    """Raised when a gate hits a halt condition that requires analyst decision before proceeding."""

    def __init__(self, gate_id: str, reason: str, payload: dict):
        self.gate_id = gate_id
        self.reason = reason
        self.payload = payload
        super().__init__(f"Gate {gate_id} HALT: {reason}")


def _resolve_tier1_halt_threshold(total: int) -> int:
    """Resolve the gapped-source count that triggers a Tier 1 halt, from env/default.

    Default is ``total`` (halt only when all Tier 1 sources gap). An explicit integer
    is clamped into ``[1, total]`` so it is always a reachable, meaningful threshold.
    """
    raw = os.getenv(_TIER1_HALT_ENV)
    if raw is None or raw.strip().lower() in {"", "all"}:
        return total
    try:
        n = int(raw)
    except ValueError:
        logger.warning("Invalid %s=%r; falling back to 'all' Tier 1 sources", _TIER1_HALT_ENV, raw)
        return total
    if total <= 0:
        return total
    return max(1, min(n, total))


def check_tier1_halt(source_records: list[SourceRecord], min_gap_to_halt: int | None = None) -> None:
    """Gate 1 halt: raises GateHaltError when enough Tier 1 sources have GAP status.

    The halt threshold is config-driven (see ``GATE_TIER1_GAP_HALT_MIN``). It defaults
    to "all Tier 1 sources gapped" — a single surviving feed (NVD, Intel471, or
    CrowdStrike) lets the pipeline proceed — but an operator can require a halt at,
    say, 2 gaps by setting the env var. Pass ``min_gap_to_halt`` to override explicitly.

    Disabled sources are not part of this check (Tier 1 sources cannot be disabled
    in this framework; the disabled flag applies to Tier 2 OSINT sources only).
    """
    tier1 = [r for r in source_records if r.tier == 1]
    gap_sources = [r for r in tier1 if r.status.startswith("GAP")]

    threshold = min_gap_to_halt if min_gap_to_halt is not None else _resolve_tier1_halt_threshold(len(tier1))

    if gap_sources and len(gap_sources) >= threshold:
        qualifier = "ALL" if threshold >= len(tier1) else f"{len(gap_sources)}/{len(tier1)}"
        raise GateHaltError(
            gate_id="1",
            reason=f"{qualifier} Tier 1 sources returned gaps or errors (halt threshold: {threshold})",
            payload={
                "gap_sources": [r.source_name for r in gap_sources],
                "halt_threshold": threshold,
                "details": [{"source": r.source_name, "status": r.status} for r in gap_sources],
            },
        )


def check_ioc_halt(ioc_list: list[IOC]) -> None:
    """Gate 2 halt: raises GateHaltError if zero IOCs were extracted across all sources."""
    if len(ioc_list) == 0:
        raise GateHaltError(
            gate_id="2",
            reason="Zero IOCs extracted across all Tier 1 sources",
            payload={"ioc_count": 0},
        )
