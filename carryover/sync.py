"""Sync AI-generated recommendations with the carryover action store.

Automation rules (preserving trustworthiness):
- NEW recommendations that don't match any open action → auto-added as open
- Existing open actions whose theme reappears in recommendations → history entry logged ("reissued")
- Nothing is ever closed or edited automatically
"""

from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher

from carryover.store import ActionStore, Action
from carryover.week import Week

logger = logging.getLogger(__name__)

# Similarity threshold for matching a recommendation to an existing action
_MATCH_THRESHOLD = 0.45

# Keywords that map recommendations to canonical action themes
_THEME_KEYWORDS: dict[str, list[str]] = {
    "iot": ["iot", "laboratory", "firmware", "instrument", "segment"],
    "mfa": ["mfa", "multifactor", "multi-factor", "vendor portal", "authentication"],
    "supply_chain": ["supply chain", "package integrity", "dependency", "dependencies", "vendor risk"],
    "perimeter": ["edge", "perimeter", "firewall", "vpn", "patch.*restrict"],
    "phishing": ["phishing", "awareness", "social engineering", "email filter"],
}


def _normalize(text: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _similarity(a: str, b: str) -> float:
    """Ratio similarity between two normalized strings."""
    return SequenceMatcher(None, _normalize(a), _normalize(b)).ratio()


def _theme_match(recommendation: str, action: Action) -> bool:
    """Check if a recommendation matches an action by keyword theme."""
    rec_lower = recommendation.lower()
    action_lower = (action.title + " " + action.description).lower()

    for _theme, keywords in _THEME_KEYWORDS.items():
        rec_hits = sum(1 for kw in keywords if kw in rec_lower)
        action_hits = sum(1 for kw in keywords if kw in action_lower)
        if rec_hits >= 2 and action_hits >= 2:
            return True
    return False


def _find_matching_action(recommendation: str, actions: list[Action]) -> Action | None:
    """Find the best matching open action for a recommendation, or None."""
    best_action = None
    best_score = 0.0

    for action in actions:
        if action.status == "complete":
            continue

        # Check theme keywords first (fast path)
        if _theme_match(recommendation, action):
            return action

        # Fall back to string similarity
        score = max(
            _similarity(recommendation, action.title),
            _similarity(recommendation, action.description),
        )
        if score > best_score:
            best_score = score
            best_action = action

    if best_score >= _MATCH_THRESHOLD:
        return best_action
    return None


def sync_recommendations(
    recommendations: list[str],
    report_week: Week,
    store: ActionStore | None = None,
    owner: str = "Unknown",
    target_offset_weeks: int = 4,
) -> dict[str, list]:
    """Sync AI recommendations with the action store.

    Args:
        recommendations: List of recommendation strings from the AI analysis
        report_week: The week this report covers
        store: ActionStore instance (default: loads from data/actions.yaml)
        owner: Default owner for new actions
        target_offset_weeks: Weeks from report_week to set as target for new actions

    Returns:
        dict with keys:
            - "reissued": list of (action_id, title) that got a reissue logged
            - "added": list of (action_id, title) that were newly created
            - "skipped": list of recommendations that matched a complete action
    """
    if store is None:
        store = ActionStore()

    all_actions = store.all_actions
    week_str = str(report_week)
    target_week = str(report_week + target_offset_weeks)

    result: dict[str, list] = {"reissued": [], "added": [], "skipped": []}

    # Track which existing actions got matched this sync (avoid double-reissue)
    matched_ids: set[str] = set()

    for rec in recommendations:
        rec = rec.strip()
        if not rec:
            continue

        match = _find_matching_action(rec, all_actions)

        if match is not None:
            if match.status == "complete":
                result["skipped"].append(rec)
                continue

            if match.id in matched_ids:
                continue
            matched_ids.add(match.id)

            # Check if we already logged this week (idempotent)
            already_logged = any(h.week == week_str for h in match.history)
            if not already_logged:
                store.update(
                    match.id,
                    week=week_str,
                    status=match.status,
                    note="Reissued in weekly report",
                )
                result["reissued"].append((match.id, match.title))
            else:
                result["reissued"].append((match.id, match.title))
        else:
            # New action — auto-add
            action = store.add(
                title=_extract_title(rec),
                description=rec,
                owner=owner,
                first_raised_week=week_str,
                target_week=target_week,
            )
            result["added"].append((action.id, action.title))

    # Log reissue for any open actions that weren't matched but are still open
    # (they're being carried forward silently)
    for action in all_actions:
        if action.status == "complete":
            continue
        if action.id in matched_ids:
            continue
        already_logged = any(h.week == week_str for h in action.history)
        if not already_logged:
            store.update(
                action.id,
                week=week_str,
                status=action.status,
                note="Carried forward (not reissued by AI this week)",
            )

    return result


def _extract_title(recommendation: str) -> str:
    """Extract a short imperative title from a recommendation string.

    Takes the first clause (up to first comma, semicolon, or ~60 chars).
    """
    # Split on first semicolon or comma that isn't inside parentheses
    for sep in (";", ","):
        if sep in recommendation:
            first_part = recommendation.split(sep)[0].strip()
            if len(first_part) >= 15:
                return first_part[:80]

    # Truncate if too long
    if len(recommendation) > 80:
        # Find word boundary near 80
        cut = recommendation[:80].rfind(" ")
        if cut > 40:
            return recommendation[:cut]
    return recommendation[:80]
