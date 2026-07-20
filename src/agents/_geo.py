"""
Country/geo attribution helpers for threat actors.

Extracted from ThreatAnalystAgent as self-contained, side-effect-free helpers.
"""


def is_china_related(actor: dict) -> bool:
    """Check if an actor is China-related."""
    country = str(actor.get("country", "")).lower()
    name = str(actor.get("actor_name", actor.get("name", ""))).lower()
    return "china" in country or "panda" in name or "apt41" in name or "apt40" in name


def is_russia_related(actor: dict) -> bool:
    """Check if an actor is Russia-related."""
    country = str(actor.get("country", "")).lower()
    name = str(actor.get("actor_name", actor.get("name", ""))).lower()
    return "russia" in country or "bear" in name or "apt29" in name or "apt28" in name


def is_nk_related(actor: dict) -> bool:
    """Check if an actor is North Korea-related."""
    country = str(actor.get("country", "")).lower()
    name = str(actor.get("actor_name", actor.get("name", ""))).lower()
    return "korea" in country or "lazarus" in name or "kimsuky" in name or "chollima" in name
