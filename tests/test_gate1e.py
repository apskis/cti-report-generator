"""Tests for Gate 1E geopolitical threat-level validation.

Regression: the actor-count check read the raw-API "origins" field, but the
CrowdStrike collector normalizes it to a "country" string — so actor_count was
always 0 and a well-supported HIGH rating (e.g. 5 North Korea actors) got a
false "unsupported HIGH" block.
"""

from __future__ import annotations

from src.gates.gate1e_ai_quality import _actor_matches_country, _validate_geopolitical_threat_levels


def _nk_actors(n: int) -> list[dict]:
    return [{"actor_name": f"CHOLLIMA-{i}", "country": "North Korea"} for i in range(n)]


class TestActorMatchesCountry:
    def test_matches_on_normalized_country_field(self):
        assert _actor_matches_country({"country": "North Korea"}, "north korea")

    def test_matches_on_raw_origins_fallback(self):
        assert _actor_matches_country({"origins": [{"value": "North Korea"}]}, "north korea")

    def test_no_match_other_country(self):
        assert not _actor_matches_country({"country": "China"}, "north korea")

    def test_empty_country_key_is_false(self):
        assert not _actor_matches_country({"country": "North Korea"}, "")


class TestGeopoliticalThreatLevels:
    def test_high_with_enough_actors_is_not_flagged(self):
        # 5 NK actors justify HIGH by actor count alone, even if the activity
        # bullets don't contain the HIGH keyword indicators.
        report = {"geopolitical_threats": [{"name": "North Korea", "level": "HIGH", "activity": ["Observed groups."]}]}
        issues = _validate_geopolitical_threat_levels(report, _nk_actors(5))
        assert issues == []

    def test_high_without_actors_or_activity_is_flagged(self):
        report = {"geopolitical_threats": [{"name": "Atlantis", "level": "HIGH", "activity": ["Quiet quarter."]}]}
        issues = _validate_geopolitical_threat_levels(report, _nk_actors(5))
        assert any("Atlantis" in i and "HIGH" in i for i in issues)

    def test_high_justified_by_activity_keywords_even_with_zero_actors(self):
        report = {
            "geopolitical_threats": [
                {"name": "Atlantis", "level": "HIGH", "activity": ["Conducted espionage campaign against biotech."]}
            ]
        }
        assert _validate_geopolitical_threat_levels(report, []) == []

    def test_low_with_many_actors_is_flagged(self):
        report = {"geopolitical_threats": [{"name": "North Korea", "level": "LOW", "activity": []}]}
        issues = _validate_geopolitical_threat_levels(report, _nk_actors(5))
        assert any("North Korea" in i and "LOW" in i for i in issues)
