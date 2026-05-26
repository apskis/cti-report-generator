"""Gate orchestrator: runs the full gate sequence with halt and escape enforcement.

The orchestrator stores each gate's GateResult so the next gate can read prior
results without gate modules importing each other directly. It enforces the
analyst clearance requirement: a gate cannot run until the previous gate has
been cleared (interactive mode), or auto-clears in run_full_sequence (automated
mode) only when status is COMPLETE with no halt or escape.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from . import (
    gate1_tier1_inventory,
    gate1a_statistics,
    gate1b_osint_triage,
    gate1c_technology_coherence,
    gate1d_source_attribution,
    gate2_ioc_extraction,
    gate3_actor_linkage,
    gate4_assembly,
    gate5_report_draft,
    gate6_adversarial_review,
)
from .escape_handler import EscapeDetectedError
from .halt import GateHaltError
from .models import GateInput, GateResult


logger = logging.getLogger(__name__)


_GATE_SEQUENCE: list[str] = ["1", "1A", "1B", "2", "3", "4", "5", "1C", "1D", "6"]

_GATE_RUNNERS = {
    "1": gate1_tier1_inventory.run,
    "1A": gate1a_statistics.run,
    "1B": gate1b_osint_triage.run,
    "1C": gate1c_technology_coherence.run,
    "1D": gate1d_source_attribution.run,
    "2": gate2_ioc_extraction.run,
    "3": gate3_actor_linkage.run,
    "4": gate4_assembly.run,
    "5": gate5_report_draft.run,
    "6": gate6_adversarial_review.run,
}


def _previous_gate(gate_id: str) -> str | None:
    idx = _GATE_SEQUENCE.index(gate_id)
    return _GATE_SEQUENCE[idx - 1] if idx > 0 else None


class GateOrchestrator:
    """Runs the CTI gate sequence gate by gate."""

    def __init__(self, llm_client, report_type: str, osint_config_path: str = "config/osint_sources.yaml"):
        self.llm_client = llm_client
        self.report_type = report_type
        self.osint_config_path = osint_config_path
        self.session: dict[str, GateResult] = {}
        self.current_gate: str = "1"
        self.cleared_gates: set[str] = set()
        self.clearance_log: list[tuple[str, str]] = []

    def _build_input(self, tier1_data: dict, osint_articles: list, period_start: str, period_end: str) -> GateInput:
        return GateInput(
            report_type=self.report_type,
            period_start=period_start,
            period_end=period_end,
            tier1_data=tier1_data or {},
            osint_articles=osint_articles or [],
            prior_results={
                **self.session,
                "osint_config_path": self.osint_config_path,
            },
        )

    def run_gate(
        self,
        gate_id: str,
        tier1_data: dict | None = None,
        osint_articles: list | None = None,
        period_start: str = "",
        period_end: str = "",
    ) -> GateResult:
        """Run the specified gate. Raises RuntimeError if the previous gate has not been cleared."""
        if gate_id not in _GATE_RUNNERS:
            raise ValueError(f"Unknown gate id: {gate_id}")

        prev = _previous_gate(gate_id)
        if prev is not None and prev not in self.cleared_gates:
            raise RuntimeError(
                f"Cannot run Gate {gate_id}: previous gate {prev} has not been cleared. "
                f"Call orchestrator.clear('{prev}') first."
            )

        gate_input = self._build_input(
            tier1_data or {},
            osint_articles or [],
            period_start,
            period_end,
        )
        runner = _GATE_RUNNERS[gate_id]

        try:
            result = runner(gate_input, self.llm_client, self.report_type)
        except GateHaltError as e:
            halt_result = GateResult(
                gate_id=gate_id,
                status="HALT",
                payload=e.payload,
                halt_reason=e.reason,
            )
            self.session[gate_id] = halt_result
            self.current_gate = gate_id
            logger.warning(f"Gate {gate_id} HALT: {e.reason}")
            raise
        except EscapeDetectedError as e:
            escape_result = GateResult(
                gate_id=gate_id,
                status="ESCAPE_DETECTED",
                payload={"offending_text": e.offending_text},
                escape_type=e.escape_type.value,
            )
            self.session[gate_id] = escape_result
            self.current_gate = gate_id
            logger.warning(f"Gate {gate_id} ESCAPE {e.escape_type.value}: {e.offending_text[:200]}")
            raise

        self.session[gate_id] = result
        self.current_gate = gate_id
        return result

    def clear(self, gate_id: str) -> None:
        """Analyst clearance: marks a gate as cleared so the next gate can run."""
        if gate_id not in self.session:
            raise RuntimeError(f"Cannot clear Gate {gate_id}: it has not been run")
        r = self.session[gate_id]
        if r.status != "COMPLETE" and not (gate_id == "6" and r.status in {"PASS", "BLOCK"}):
            raise RuntimeError(
                f"Cannot clear Gate {gate_id}: status is {r.status}, not COMPLETE"
            )
        self.cleared_gates.add(gate_id)
        timestamp = datetime.now(timezone.utc).isoformat()
        self.clearance_log.append((gate_id, timestamp))
        logger.info(f"Gate {gate_id} cleared at {timestamp}")

    def get_session_summary(self) -> dict:
        return {
            "current_gate": self.current_gate,
            "cleared_gates": sorted(self.cleared_gates),
            "gate_statuses": {gid: r.status for gid, r in self.session.items()},
            "clearance_log": list(self.clearance_log),
        }

    def run_full_sequence(
        self,
        tier1_data: dict,
        osint_articles: list,
        period_start: str,
        period_end: str,
    ) -> GateResult:
        """Run all gates non-interactively. Gates auto-clear on COMPLETE; HALT/ESCAPE raises."""
        for gate_id in _GATE_SEQUENCE:
            result = self.run_gate(
                gate_id,
                tier1_data=tier1_data,
                osint_articles=osint_articles,
                period_start=period_start,
                period_end=period_end,
            )
            # Gate 6 yields PASS or BLOCK rather than COMPLETE; auto-clear either way to allow downstream inspection.
            if result.status in {"COMPLETE", "PASS", "BLOCK"}:
                self.cleared_gates.add(gate_id)
                self.clearance_log.append((gate_id, datetime.now(timezone.utc).isoformat() + " [auto]"))
            else:
                raise RuntimeError(
                    f"Gate {gate_id} returned non-clearable status {result.status} during automated sequence"
                )
        return self.session["6"]
