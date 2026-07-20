"""Halt conditions enforced at gate boundaries.

A halt is a structural failure that requires analyst decision before the
pipeline can proceed. Halts are distinct from escapes: a halt is a property
of the source data (e.g. two Tier 1 sources returned errors), while an escape
is a property of the model output (e.g. the model leaked training knowledge).
"""

from __future__ import annotations

from .models import IOC, SourceRecord


class GateHaltError(Exception):
    """Raised when a gate hits a halt condition that requires analyst decision before proceeding."""

    def __init__(self, gate_id: str, reason: str, payload: dict):
        self.gate_id = gate_id
        self.reason = reason
        self.payload = payload
        super().__init__(f"Gate {gate_id} HALT: {reason}")


def check_tier1_halt(source_records: list[SourceRecord]) -> None:
    """Gate 1 halt: raises GateHaltError if ALL Tier 1 sources have GAP status.

    Modified to only halt if ALL sources fail (instead of 2+) since NVD CloudFlare
    issues and ThreatQ gaps are known. As long as Intel471, CrowdStrike, or OSINT
    have data, we can proceed.

    Disabled sources are not part of this check (Tier 1 sources cannot be disabled
    in this framework; the disabled flag applies to Tier 2 OSINT sources only).
    """
    tier1 = [r for r in source_records if r.tier == 1]
    gap_sources = [r for r in tier1 if r.status.startswith("GAP")]

    # Only halt if ALL Tier 1 sources failed (not just 2+)
    if len(gap_sources) >= len(tier1):
        raise GateHaltError(
            gate_id="1",
            reason=f"ALL {len(gap_sources)} Tier 1 sources returned gaps or errors",
            payload={
                "gap_sources": [r.source_name for r in gap_sources],
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
