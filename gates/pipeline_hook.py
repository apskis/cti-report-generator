"""Shared gate framework pipeline hook for both Azure Functions and CLI.

Provides run_gate_framework_over_collected_data() for reuse across function_app.py
and test_local.py. Handles all exceptions internally and returns structured results
so the caller can print summaries and decide whether to write the .docx.

Supports both automated and interactive modes for gate execution.
"""
from __future__ import annotations

import logging
from datetime import date, timedelta

from .escape_handler import EscapeDetectedError
from .halt import GateHaltError
from .llm_adapter import StructuralLLMClient
from .models import GateResult
from .orchestrator import GateOrchestrator

logger = logging.getLogger(__name__)


def run_gate_framework_over_collected_data(
    report_type: str,
    data_by_source: dict,
    osint_articles: list,
    period_days: int,
    interactive_mode: bool = False,
    interactive_callback=None,
    credentials: dict = None,  # NEW: Pass credentials for Gate 5
) -> tuple[bool, dict, dict[str, GateResult]]:
    """Run the gate framework over collected data.

    Args:
        report_type: "weekly" or "quarterly"
        data_by_source: Dictionary mapping source names to lists of records
        osint_articles: List of OSINT article dicts
        period_days: Number of days in the reporting period (7 for weekly, 90 for quarterly)
        interactive_mode: If True, pause after each gate for manual review
        interactive_callback: Function called after each gate for user approval
                             Should return True to continue, False to abort
        credentials: Dictionary with openai_endpoint and openai_key for Gate 5

    Returns:
        (publish_ok, info, session) where:
        - publish_ok: True if Gate 6 PASS, False if BLOCK/HALT/ESCAPE
        - info: Dictionary with diagnostic details on block/halt/escape
        - session: Orchestrator's session dict (gate_id -> GateResult) for printing summary
    """
    period_end = date.today()
    period_start = period_end - timedelta(days=period_days)

    tier1_data = {
        "ThreatQ": data_by_source.get("ThreatQ", []),
        "NVD": data_by_source.get("NVD", []),
        "Intel471": data_by_source.get("Intel471", []),
        "Rapid7": data_by_source.get("Rapid7", []),
        "CrowdStrike": data_by_source.get("CrowdStrike", []),
    }

    orchestrator = GateOrchestrator(
        llm_client=StructuralLLMClient(),
        report_type=report_type.upper(),
    )
    
    # Store credentials in session so Gate 5 can access them
    if credentials:
        orchestrator.session["credentials"] = type('obj', (object,), {
            'payload': {'credentials': credentials}
        })()

    if interactive_mode:
        # Interactive mode: run gates one by one with manual clearance
        gate_sequence = ["1", "1A", "1B", "2", "3", "4", "5", "1C", "6"]
        
        for gate_id in gate_sequence:
            try:
                result = orchestrator.run_gate(
                    gate_id,
                    tier1_data=tier1_data,
                    osint_articles=osint_articles or [],
                    period_start=period_start.isoformat(),
                    period_end=period_end.isoformat(),
                )
                
                # Call interactive callback for user approval
                if interactive_callback:
                    should_continue = interactive_callback(gate_id, result, orchestrator.session)
                    if not should_continue:
                        return (
                            False,
                            {"user_abort": True, "aborted_at_gate": gate_id},
                            orchestrator.session,
                        )
                
                # Clear the gate to proceed to next
                orchestrator.clear(gate_id)
                
            except (GateHaltError, EscapeDetectedError) as e:
                # Exception handling same as automated mode
                break
        
        # After all gates, check Gate 6 result
        if "6" not in orchestrator.session:
            return (
                False,
                {"incomplete": True, "message": "Gate sequence did not complete"},
                orchestrator.session,
            )
        
        gate6 = orchestrator.session["6"]
    else:
        # Automated mode: run full sequence
        try:
            gate6 = orchestrator.run_full_sequence(
                tier1_data=tier1_data,
                osint_articles=osint_articles or [],
                period_start=period_start.isoformat(),
                period_end=period_end.isoformat(),
            )
        except GateHaltError as e:
            logger.warning(f"Gate framework HALT at Gate {e.gate_id}: {e.reason}")
            return (
                False,
                {"halt_gate": e.gate_id, "halt_reason": e.reason, "halt_payload": e.payload},
                orchestrator.session,
            )
        except EscapeDetectedError as e:
            logger.warning(
                f"Gate framework ESCAPE at Gate {e.gate_id} ({e.escape_type.value}): {e.offending_text[:200]}"
            )
            return (
                False,
                {
                    "escape_gate": e.gate_id,
                    "escape_type": e.escape_type.value,
                    "offending_text": e.offending_text,
                },
                orchestrator.session,
            )

    if gate6.status == "BLOCK":
        track_a = gate6.payload.get("track_a", [])
        logger.warning(f"Gate 6 BLOCK with {len(track_a)} Track A findings: {track_a}")
        return (
            False,
            {"gate6_status": "BLOCK", "track_a": track_a, "track_b": gate6.payload.get("track_b", [])},
            orchestrator.session,
        )

    return (
        True,
        {"gate6_status": "PASS", "track_b": gate6.payload.get("track_b", [])},
        orchestrator.session,
    )
