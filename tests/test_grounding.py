"""Tests for src/gates/grounding.py — deterministic source-grounding.

These verify the anti-hallucination primitive: fabricated CVEs, threat actors,
and named victims that do not resolve to any collected source record are caught,
while claims backed by real source data pass. All pure Python, no LLM.

NEW (Tier 2): Tests for stable record IDs, quote validation, and citation checking.
"""

from __future__ import annotations

from src.gates.grounding import (
    SourceIndex,
    build_source_index,
    normalize_whitespace,
    rederive_statistics,
    validate_quote_in_record,
    validate_quote_in_source,
    verify_report_grounding,
)

# ---------------------------------------------------------------------------
# Fixtures: a small but representative slice of collected source data.
# ---------------------------------------------------------------------------


def _tier1_data() -> dict:
    return {
        "nvd_cves": [
            {"cve_id": "CVE-2024-1234", "description": "Heap overflow in Acme Server"},
            {"cve_id": "CVE-2024-5678", "description": "Auth bypass"},
        ],
        "crowdstrike_actors": [
            {"actor_name": "COZY BEAR", "cve_ids": ["CVE-2023-9999"]},
        ],
        "intel471_reports": [
            {"uid": "r1", "threat_actor": "FIN7", "threat_type": "ransomware"},
        ],
    }


def _osint_articles() -> list[dict]:
    return [
        {
            "article_id": "a1",
            "title": "Morrison & Foerster LLP discloses data breach",
            "summary": "Law firm Morrison & Foerster reported unauthorized access.",
            "url": "https://example.com/mofo",
        },
    ]


# ---------------------------------------------------------------------------
# build_source_index
# ---------------------------------------------------------------------------


class TestBuildSourceIndex:
    def test_collects_cve_ids_from_fields(self):
        idx = build_source_index(_tier1_data())
        assert idx.has_cve("CVE-2024-1234")
        assert idx.has_cve("CVE-2024-5678")
        # From a cve_ids list on the actor record.
        assert idx.has_cve("CVE-2023-9999")

    def test_cve_lookup_is_case_insensitive(self):
        idx = build_source_index(_tier1_data())
        assert idx.has_cve("cve-2024-1234")

    def test_collects_actor_names_from_known_fields(self):
        idx = build_source_index(_tier1_data())
        assert "cozy bear" in idx.actor_names
        assert "fin7" in idx.actor_names

    def test_cve_in_free_text_is_grounded(self):
        data = {"reports": [{"body": "We observed exploitation of CVE-2024-0001 in the wild"}]}
        idx = build_source_index(data)
        assert idx.has_cve("CVE-2024-0001")

    def test_osint_text_included_in_blob(self):
        idx = build_source_index(_tier1_data(), _osint_articles())
        assert "morrison" in idx.text_blob

    def test_handles_empty_and_none(self):
        idx = build_source_index({}, None)
        assert idx.cve_ids == set()
        assert idx.actor_names == set()

    def test_skips_placeholder_actor_names(self):
        data = {"x": [{"actor_name": "Unknown"}, {"actor_name": "N/A"}]}
        idx = build_source_index(data)
        assert idx.actor_names == set()


# ---------------------------------------------------------------------------
# verify_report_grounding — the core catch
# ---------------------------------------------------------------------------


class TestVerifyReportGrounding:
    def test_grounded_report_passes(self):
        idx = build_source_index(_tier1_data(), _osint_articles())
        report = {
            "cve_analysis": [{"cve_id": "CVE-2024-1234"}, {"cve_id": "CVE-2024-5678"}],
            "apt_activity": [{"actor_name": "COZY BEAR"}, {"actor_name": "FIN7"}],
            "industry_incidents": [{"organization": "Morrison & Foerster LLP"}],
        }
        assert verify_report_grounding(report, idx) == []

    def test_fabricated_cve_is_caught(self):
        idx = build_source_index(_tier1_data())
        report = {"cve_analysis": [{"cve_id": "CVE-2024-1234"}, {"cve_id": "CVE-2099-0000"}]}
        findings = verify_report_grounding(report, idx)
        assert len(findings) == 1
        assert "CVE-2099-0000" in findings[0]

    def test_fabricated_actor_is_caught(self):
        idx = build_source_index(_tier1_data())
        report = {"apt_activity": [{"actor_name": "PHANTOM SERPENT"}]}
        findings = verify_report_grounding(report, idx)
        assert len(findings) == 1
        assert "PHANTOM SERPENT" in findings[0]

    def test_fabricated_victim_is_caught(self):
        idx = build_source_index(_tier1_data(), _osint_articles())
        report = {"industry_incidents": [{"organization": "Globex Pharmaceuticals Inc"}]}
        findings = verify_report_grounding(report, idx)
        assert len(findings) == 1
        assert "Globex" in findings[0]

    def test_grounded_victim_from_osint_passes(self):
        idx = build_source_index(_tier1_data(), _osint_articles())
        report = {"industry_incidents": [{"organization": "Morrison & Foerster LLP"}]}
        assert verify_report_grounding(report, idx) == []

    def test_actor_token_match_tolerates_normalization(self):
        # Source has "COZY BEAR"; report writes "Cozy Bear (APT29)" — the shared
        # distinctive tokens keep it grounded.
        idx = build_source_index(_tier1_data())
        report = {"apt_activity": [{"actor_name": "Cozy Bear"}]}
        assert verify_report_grounding(report, idx) == []

    def test_placeholder_actor_names_not_flagged(self):
        idx = build_source_index(_tier1_data())
        report = {"apt_activity": [{"actor_name": "Unknown"}, {"actor_name": "Unattributed"}]}
        assert verify_report_grounding(report, idx) == []

    def test_placeholder_victim_names_not_flagged(self):
        idx = build_source_index(_tier1_data())
        report = {"industry_incidents": [{"organization": "Undisclosed"}, {"organization": "N/A"}]}
        assert verify_report_grounding(report, idx) == []

    def test_generic_stopword_name_still_flagged(self):
        # A fabricated name whose only shared tokens are stopwords must NOT be
        # treated as grounded.
        idx = build_source_index({"x": [{"actor_name": "COZY BEAR"}]})
        report = {"apt_activity": [{"actor_name": "The Threat Group"}]}
        findings = verify_report_grounding(report, idx)
        assert len(findings) == 1

    def test_non_dict_entries_skipped(self):
        idx = build_source_index(_tier1_data())
        report = {"cve_analysis": ["not a dict", None], "apt_activity": [42]}
        assert verify_report_grounding(report, idx) == []

    def test_empty_report_passes(self):
        idx = build_source_index(_tier1_data())
        assert verify_report_grounding({}, idx) == []


# ---------------------------------------------------------------------------
# rederive_statistics — internal-consistency re-derivation
# ---------------------------------------------------------------------------


class TestRederiveStatistics:
    def test_matching_stats_pass(self):
        report = {
            "statistics": {"threat_actors": 2, "peer_incidents": 1, "total_cves": 3},
            "apt_activity": [{"actor_name": "A"}, {"actor_name": "B"}],
            "industry_incidents": [{"organization": "X"}],
            "cve_analysis": [{"cve_id": "1"}, {"cve_id": "2"}, {"cve_id": "3"}],
        }
        assert rederive_statistics(report) == []

    def test_inflated_actor_count_caught(self):
        report = {
            "statistics": {"threat_actors": 9},
            "apt_activity": [{"actor_name": "A"}],
        }
        findings = rederive_statistics(report)
        assert len(findings) == 1
        assert "threat_actors" in findings[0]
        assert "9" in findings[0]

    def test_multiple_mismatches(self):
        report = {
            "statistics": {"threat_actors": 5, "peer_incidents": 5, "total_cves": 5},
            "apt_activity": [{"actor_name": "A"}],
            "industry_incidents": [],
            "cve_analysis": [{"cve_id": "1"}],
        }
        assert len(rederive_statistics(report)) == 3

    def test_no_statistics_block_is_noop(self):
        report = {"apt_activity": [{"actor_name": "A"}]}
        assert rederive_statistics(report) == []

    def test_non_int_statistic_ignored(self):
        report = {"statistics": {"threat_actors": "many"}, "apt_activity": []}
        assert rederive_statistics(report) == []


# ---------------------------------------------------------------------------
# SourceIndex.mentions direct behavior
# ---------------------------------------------------------------------------


class TestSourceIndexMentions:
    def test_empty_name_is_grounded(self):
        idx = SourceIndex()
        assert idx.mentions("") is True
        assert idx.mentions(None) is True

    def test_whole_name_substring(self):
        idx = SourceIndex(text_blob="acme corp was breached last tuesday")
        assert idx.mentions("Acme Corp") is True

    def test_known_actor_name(self):
        idx = SourceIndex(actor_names={"lazarus"})
        assert idx.mentions("Lazarus") is True


# ---------------------------------------------------------------------------
# Tier 2 additions: stable record IDs, quote validation, citation checking
# ---------------------------------------------------------------------------


class TestStableRecordIds:
    def test_records_have_stable_ids(self):
        data = {
            "nvd_cves": [{"cve_id": "CVE-2024-1234"}, {"cve_id": "CVE-2024-5678"}],
            "crowdstrike_actors": [{"actor_name": "COZY BEAR"}],
        }
        idx = build_source_index(data)
        # Records should be indexed by source_key + index
        assert idx.get_record("nvd_cves_0") is not None
        assert idx.get_record("nvd_cves_1") is not None
        assert idx.get_record("crowdstrike_actors_0") is not None

    def test_osint_articles_have_stable_ids(self):
        osint = [
            {"article_id": "a1", "title": "Test Article"},
            {"article_id": "a2", "title": "Another Article"},
        ]
        idx = build_source_index({}, osint)
        assert idx.get_record("osint_0") is not None
        assert idx.get_record("osint_1") is not None

    def test_get_nonexistent_record_returns_none(self):
        idx = build_source_index(_tier1_data())
        assert idx.get_record("nonexistent_999") is None


class TestRecordContainsEntity:
    def test_record_contains_cve(self):
        idx = build_source_index(_tier1_data())
        # nvd_cves_0 should contain CVE-2024-1234
        assert idx.record_contains_entity("nvd_cves_0", "CVE-2024-1234") is True
        assert idx.record_contains_entity("nvd_cves_0", "CVE-9999-9999") is False

    def test_record_contains_actor(self):
        idx = build_source_index(_tier1_data())
        # crowdstrike_actors_0 should contain COZY BEAR
        assert idx.record_contains_entity("crowdstrike_actors_0", "COZY BEAR") is True
        assert idx.record_contains_entity("crowdstrike_actors_0", "PHANTOM") is False

    def test_nonexistent_record_returns_false(self):
        idx = build_source_index(_tier1_data())
        assert idx.record_contains_entity("nonexistent_999", "anything") is False


class TestQuoteValidation:
    def test_exact_quote_found(self):
        idx = build_source_index(_tier1_data())
        # Quote from the NVD description
        assert validate_quote_in_source("Heap overflow in Acme Server", idx) is True

    def test_quote_with_normalized_whitespace_found(self):
        data = {"reports": [{"body": "The   vulnerability    is   critical"}]}
        idx = build_source_index(data)
        # Extra whitespace should be normalized
        assert validate_quote_in_source("The vulnerability is critical", idx) is True

    def test_quote_case_insensitive(self):
        data = {"reports": [{"body": "COZY BEAR is a threat actor"}]}
        idx = build_source_index(data)
        assert validate_quote_in_source("cozy bear is a threat actor", idx) is True

    def test_fabricated_quote_not_found(self):
        idx = build_source_index(_tier1_data())
        assert validate_quote_in_source("This quote does not exist anywhere", idx) is False

    def test_partial_quote_found(self):
        data = {"reports": [{"body": "The actor exploited CVE-2024-1234 in the wild"}]}
        idx = build_source_index(data)
        # Partial substring should match
        assert validate_quote_in_source("exploited CVE-2024-1234", idx) is True

    def test_empty_quote_returns_false(self):
        idx = build_source_index(_tier1_data())
        assert validate_quote_in_source("", idx) is False
        assert validate_quote_in_source("   ", idx) is False


class TestQuoteInRecord:
    def test_quote_found_in_cited_record(self):
        idx = build_source_index(_tier1_data())
        assert validate_quote_in_record("Heap overflow in Acme Server", "nvd_cves_0", idx) is True

    def test_quote_in_corpus_but_wrong_record_is_false(self):
        # "COZY BEAR" is in crowdstrike_actors_0, NOT in nvd_cves_0. A corpus-wide check
        # would pass; the record-specific check must reject it.
        idx = build_source_index(_tier1_data())
        assert validate_quote_in_source("COZY BEAR", idx) is True
        assert validate_quote_in_record("COZY BEAR", "nvd_cves_0", idx) is False

    def test_unknown_record_is_false(self):
        idx = build_source_index(_tier1_data())
        assert validate_quote_in_record("anything", "nonexistent_999", idx) is False

    def test_empty_quote_is_false(self):
        idx = build_source_index(_tier1_data())
        assert validate_quote_in_record("", "nvd_cves_0", idx) is False


class TestNormalizeWhitespace:
    def test_collapses_multiple_spaces(self):
        assert normalize_whitespace("a    b    c") == "a b c"

    def test_lowercases(self):
        assert normalize_whitespace("UPPER case MiXeD") == "upper case mixed"

    def test_strips_leading_trailing(self):
        assert normalize_whitespace("  text  ") == "text"

    def test_handles_newlines_and_tabs(self):
        assert normalize_whitespace("line1\n\tline2\r\nline3") == "line1 line2 line3"
