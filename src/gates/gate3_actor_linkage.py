"""Gate 3: Actor and campaign linkage using only source-provided attribution.

For each IOC from Gate 2, walks the raw Tier 1 records to find a source that
explicitly names an actor for that IOC. If no source names an actor, the IOC
is grouped under [UNATTRIBUTED]. Actor names like APT29, Lazarus, or Sandworm
are NEVER injected from training knowledge; only strings present in the
source data appear in this gate's output.
"""

from __future__ import annotations

from .escape_handler import detect_gate_bleed, detect_prose_leakage
from .models import IOC, ActorLink, GateInput, GateResult
from .prompts import GATE_3_PROMPT_TEMPLATE, SYSTEM_PROMPT_GATE_3


def _record_matches_ioc(record: dict, ioc: IOC) -> bool:
    candidates = []
    for key in ("indicator", "value", "ioc"):
        v = record.get(key)
        if isinstance(v, str):
            candidates.append(v)
    for field in ("indicators", "iocs", "indicator_list"):
        items = record.get(field)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    v = item.get("value") or item.get("indicator")
                    if isinstance(v, str):
                        candidates.append(v)
                elif isinstance(item, str):
                    candidates.append(item)
    return ioc.value in candidates


def _pull_actor_fields(record: dict) -> dict[str, str | None]:
    actor = record.get("actor") or record.get("actor_name") or record.get("threat_actor") or record.get("adversary")
    if isinstance(actor, dict):
        actor = actor.get("name") or actor.get("alias")

    campaign = record.get("campaign") or record.get("campaign_name")
    confidence = record.get("confidence") or record.get("attribution_confidence")
    region = record.get("region") or record.get("origin_country") or record.get("country")

    def _str_or_none(x):
        if x in (None, ""):
            return None
        return str(x)

    return {
        "actor": _str_or_none(actor),
        "campaign": _str_or_none(campaign),
        "confidence": _str_or_none(confidence),
        "region": _str_or_none(region),
    }


def _link_ioc(ioc: IOC, tier1_data: dict, include_region: bool) -> list[ActorLink]:
    """Return one ActorLink per source that names an actor for this IOC.

    If no source names an actor, return a single [UNATTRIBUTED] link.
    """
    links: list[ActorLink] = []
    for source_name in ioc.sources:
        raw = tier1_data.get(source_name)
        if not isinstance(raw, list):
            continue
        for rec in raw:
            if not isinstance(rec, dict) or not _record_matches_ioc(rec, ioc):
                continue
            fields = _pull_actor_fields(rec)
            if not fields["actor"]:
                continue
            links.append(
                ActorLink(
                    ioc_value=ioc.value,
                    actor_name=fields["actor"],
                    attribution_source=source_name,
                    campaign=fields["campaign"],
                    confidence=fields["confidence"],
                    region=fields["region"] if include_region else None,
                )
            )

    if not links:
        return [
            ActorLink(
                ioc_value=ioc.value,
                actor_name="[UNATTRIBUTED]",
                attribution_source="[NONE]",
                campaign=None,
                confidence=None,
                region=None,
            )
        ]
    return links


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    gate1 = input.prior_results.get("1")
    gate2 = input.prior_results.get("2")
    if gate1 is None or gate2 is None:
        raise RuntimeError("Gate 3 requires Gate 1 and Gate 2 GateResults in input.prior_results")

    iocs: list[IOC] = gate2.payload.get("iocs", [])
    include_region = report_type.upper() == "QUARTERLY"

    all_links: list[ActorLink] = []
    for ioc in iocs:
        all_links.extend(_link_ioc(ioc, input.tier1_data, include_region))

    # Build compact summaries for the LLM
    gate1_summary = "\n".join(
        f"{r.source_name}: {r.records_returned} records" for r in gate1.payload.get("tier1_sources", [])
    )
    gate2_summary = "\n".join(f"{i.ioc_type} | {i.value} | {','.join(i.sources)}" for i in iocs)

    user_prompt = GATE_3_PROMPT_TEMPLATE.format(
        gate1_output=gate1_summary,
        gate2_output=gate2_summary,
        report_type=report_type,
    )
    llm_text = llm_client.complete(SYSTEM_PROMPT_GATE_3, user_prompt)

    detect_gate_bleed(llm_text, expected_gate_id="3")
    detect_prose_leakage(llm_text, gate_id="3")

    return GateResult(
        gate_id="3",
        status="COMPLETE",
        payload={
            "actor_links": all_links,
            "linkage_text": llm_text,
            "report_type": report_type,
        },
        awaiting_clearance=True,
    )
