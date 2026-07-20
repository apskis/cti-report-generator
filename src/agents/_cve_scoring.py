"""
Deterministic CVE priority scoring and related self-contained helpers.

Extracted from ThreatAnalystAgent as side-effect-free, self-contained functions.
"""

import re
from typing import Any


def collect_all_cve_ids(cve_data: list[dict]) -> set:
    """Gather all unique CVE IDs across data sources for enrichment lookups."""
    ids = set()
    for cve in cve_data:
        cve_id = cve.get("cve_id", "")
        if cve_id:
            ids.add(cve_id)
    return ids


def extract_count(exposure_str: str) -> int:
    """Extract numeric count from exposure string like '7 systems'."""
    try:
        return int(exposure_str.split()[0])
    except (ValueError, IndexError):
        return 0


def compute_priority(
    cve_entry: dict[str, Any],
    kev_lookup: dict[str, dict],
    epss_lookup: dict[str, dict],
    apt_cve_map: dict[str, str],
) -> tuple:
    """
    Deterministic weighted priority scoring (0-100 scale).

    Weights:
        CVSS severity   0-30
        EPSS score       0-30
        CISA KEV         0-20
        Threat actor     0-15
        Exposure         0-5

    Returns (priority_label, numeric_score, justification_string).
    """
    cve_id = cve_entry.get("cve_id", "")
    score = 0
    factors = []

    # --- CVSS severity (0-30) ---
    severity = (cve_entry.get("severity") or "").upper()
    cvss_raw = cve_entry.get("cvss_score")
    try:
        cvss = float(cvss_raw) if cvss_raw is not None else None
    except (TypeError, ValueError):
        cvss = None

    if cvss is not None:
        if cvss >= 9.0:
            score += 30
            factors.append(f"CVSS {cvss}")
        elif cvss >= 7.0:
            score += 20
            factors.append(f"CVSS {cvss}")
        elif cvss >= 4.0:
            score += 10
            factors.append(f"CVSS {cvss}")
        else:
            score += 5
            factors.append(f"CVSS {cvss}")
    else:
        if severity in ("CRITICAL",):
            score += 30
            factors.append("Critical severity")
        elif severity in ("HIGH", "SEVERE"):
            score += 20
            factors.append("High severity")
        elif severity in ("MEDIUM", "MODERATE"):
            score += 10
            factors.append("Medium severity")
        else:
            score += 5
            factors.append(severity or "Unknown severity")

    # --- EPSS (0-30) ---
    epss_entry = epss_lookup.get(cve_id)
    if epss_entry:
        epss_score = epss_entry["epss"]
        if epss_score >= 0.6:
            score += 30
            factors.append(f"EPSS {epss_score:.0%}")
        elif epss_score >= 0.2:
            score += 20
            factors.append(f"EPSS {epss_score:.0%}")
        elif epss_score >= 0.04:
            score += 10
            factors.append(f"EPSS {epss_score:.1%}")
        else:
            score += 3
            factors.append(f"EPSS {epss_score:.2%}")

    # --- CISA KEV (0-20) ---
    kev = kev_lookup.get(cve_id)
    if kev:
        score += 20
        factors.append("CISA KEV")

    # --- Threat actor relevance (0-15) ---
    actor_label = apt_cve_map.get(cve_id)
    if actor_label:
        if "crowdstrike" in actor_label.lower() or "apt" in actor_label.lower():
            score += 15
            factors.append(f"Actor: {actor_label}")
        else:
            score += 10
            factors.append(f"Intel471: {actor_label}")

    # --- Exposure (0-5) ---
    exposure_str = cve_entry.get("exposure", "0")
    try:
        asset_count = int(str(exposure_str).split()[0])
    except (ValueError, IndexError):
        asset_count = 0
    if asset_count >= 5:
        score += 5
        factors.append(f"{asset_count} assets")
    elif asset_count >= 1:
        score += 2
        factors.append(f"{asset_count} asset{'s' if asset_count > 1 else ''}")

    # --- Thresholds ---
    if score >= 60:
        label = "P1"
    elif score >= 30:
        label = "P2"
    else:
        label = "P3"

    justification = "; ".join(factors) + f" [score {score}]"
    return label, score, justification


def build_apt_cve_map(
    intel471_data: list[dict],
    crowdstrike_data: list[dict],
) -> dict[str, str]:
    """
    Build CVE-ID -> actor-label mapping from Intel471 reports and
    CrowdStrike actor data so the priority scorer can give credit for
    threat-actor association.
    """
    apt_cve_map: dict[str, str] = {}
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

    for item in intel471_data or []:
        actor = item.get("threat_actor", "")
        if not actor or actor == "Unknown":
            actor = item.get("threat_type", "Intel471 report")
        text = item.get("summary", "") + " " + item.get("description", "")
        for cve_id in cve_pattern.findall(text):
            if cve_id not in apt_cve_map:
                apt_cve_map[cve_id] = actor

    for actor in crowdstrike_data or []:
        actor_name = actor.get("actor_name", actor.get("name", ""))
        if not actor_name:
            continue
        for field in ("description", "summary", "rich_text_description"):
            text = actor.get(field, "")
            if isinstance(text, str):
                for cve_id in cve_pattern.findall(text):
                    apt_cve_map[cve_id] = f"{actor_name} (CrowdStrike)"

    return apt_cve_map


def extract_product_from_description(description: str) -> str:
    """Try to extract product name from CVE description text."""
    if not description:
        return ""
    import re

    patterns = [
        r"^([\w\s]+(?:Server|Client|Browser|Framework|Library|Engine|Platform))",
        r"(?:in|affecting|vulnerability in)\s+([\w\s\.]+?)(?:\s+(?:before|prior|through|allows|via|could))",
    ]
    for pattern in patterns:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            product = match.group(1).strip()
            if len(product) > 3 and len(product) < 50:
                return product
    return ""
