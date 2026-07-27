"""
Unit tests for CTI collectors.

These tests use mocked HTTP responses to test collector logic
without making actual API calls.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from src.collectors.crowdstrike_collector import CrowdStrikeCollector
from src.collectors.intel471_collector import Intel471Collector

# Import collectors
from src.collectors.nvd_collector import NVDCollector
from src.collectors.registry import get_collector, list_available_collectors

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_credentials():
    """Sample credentials for testing."""
    return {
        "nvd_key": "test-nvd-key",
        "intel471_email": "test@example.com",
        "intel471_key": "test-intel471-key",
        "crowdstrike_id": "test-client-id",
        "crowdstrike_secret": "test-client-secret",
        "crowdstrike_base_url": "https://api.crowdstrike.com",
    }


@pytest.fixture
def nvd_api_response():
    """Sample NVD API response."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "published": "2024-01-15T10:00:00.000",
                    "descriptions": [{"lang": "en", "value": "A critical vulnerability in Example Software"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-5678",
                    "published": "2024-01-16T10:00:00.000",
                    "descriptions": [{"lang": "en", "value": "A high severity vulnerability"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "published": "2024-01-17T10:00:00.000",
                    "descriptions": [{"lang": "en", "value": "A low severity vulnerability"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.1, "baseSeverity": "LOW"}}]},
                }
            },
        ]
    }


@pytest.fixture
def intel471_reports_response():
    """Sample Intel471 reports response."""
    return {
        "reports": [
            {
                "uid": "report-123",
                "subject": "Healthcare sector targeted by ransomware group",
                "tags": ["healthcare", "ransomware"],
                "actorHandle": "APT-Healthcare",
                "created": 1705320000000,  # Milliseconds
                "documentType": "Intelligence Report",
                "admiraltyCode": "B1",
                "motivation": ["Financial"],
                "portalReportUrl": "https://portal.intel471.com/report/123",
            }
        ]
    }


@pytest.fixture
def intel471_indicators_response():
    """Sample Intel471 indicators response."""
    return {
        "indicators": [
            {
                "uid": "indicator-456",
                "last_updated": 1705320000000,
                "data": {
                    "indicator_type": "domain",
                    "indicator_data": {"domain": "malicious.example.com"},
                    "confidence": "High",
                    "threat": {"data": {"family": "Ransomware-X"}},
                },
            }
        ]
    }


@pytest.fixture
def crowdstrike_token_response():
    """Sample CrowdStrike OAuth token response."""
    return {"access_token": "test-token-12345"}


@pytest.fixture
def crowdstrike_actors_response():
    """Sample CrowdStrike actors response."""
    return {
        "resources": [
            {
                "name": "FANCY BEAR",
                "origins": [{"value": "Russia"}],
                "motivations": ["Espionage"],
                "kill_chain": ["Reconnaissance", "Weaponization", "Delivery"],
                "target_industries": ["Healthcare", "Technology"],
                "last_modified_date": "2024-01-15T10:00:00Z",
            }
        ]
    }


# =============================================================================
# NVD Collector Tests
# =============================================================================


class TestNVDCollector:
    """Tests for NVD collector."""

    def test_source_name(self, mock_credentials):
        """Test source name property."""
        collector = NVDCollector(mock_credentials)
        assert collector.source_name == "NVD"

    @pytest.mark.asyncio
    async def test_collect_success(self, mock_credentials, nvd_api_response):
        """Test successful CVE collection."""
        collector = NVDCollector(mock_credentials)

        with patch("src.collectors.nvd_collector.HTTPClient") as MockHTTPClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=nvd_api_response)
            MockHTTPClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockHTTPClient.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await collector.collect()

            assert result.success is True
            assert result.source == "NVD"
            # The collector now returns ALL severities; severity/exploitation filtering
            # happens downstream during enrichment (see nvd_collector._parse_* docstrings).
            assert result.record_count == 3
            assert len(result.data) == 3

            # Verify CVE IDs — all severities present, including LOW
            cve_ids = [cve["cve_id"] for cve in result.data]
            assert "CVE-2024-1234" in cve_ids
            assert "CVE-2024-5678" in cve_ids
            assert "CVE-2024-9999" in cve_ids  # LOW severity retained for downstream filtering

    def test_extract_cvss_v31(self, mock_credentials):
        """Test CVSS extraction from v3.1 metrics."""
        collector = NVDCollector(mock_credentials)
        cve = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}
        score, severity = collector._extract_cvss(cve)
        assert score == 9.8
        assert severity == "CRITICAL"

    def test_extract_cvss_v2_fallback(self, mock_credentials):
        """Test CVSS extraction falls back to v2."""
        collector = NVDCollector(mock_credentials)
        cve = {"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 9.5}}]}}
        score, severity = collector._extract_cvss(cve)
        assert score == 9.5
        assert severity == "CRITICAL"  # Derived from score


# =============================================================================
# Intel471 Collector Tests
# =============================================================================


class TestIntel471Collector:
    """Tests for Intel471 collector."""

    def test_source_name(self, mock_credentials):
        """Test source name property."""
        collector = Intel471Collector(mock_credentials)
        assert collector.source_name == "Intel471"

    def test_is_relevant_biotech(self, mock_credentials):
        """Test biotech relevance detection."""
        collector = Intel471Collector(mock_credentials)

        # Should be relevant
        assert collector._is_relevant_biotech("Healthcare sector under attack") is True
        assert collector._is_relevant_biotech("Attack on hospital systems") is True
        assert collector._is_relevant_biotech("Generic attack", ["healthcare", "ransomware"]) is True

        # Should not be relevant
        assert collector._is_relevant_biotech("Financial sector attack") is False

    def test_parse_report(self, mock_credentials, intel471_reports_response):
        """Test report parsing."""
        collector = Intel471Collector(mock_credentials)
        report = intel471_reports_response["reports"][0]

        parsed = collector._parse_report(report)

        assert parsed["source"] == "Intel471"
        assert parsed["threat_actor"] == "APT-Healthcare"
        assert parsed["threat_type"] == "Intelligence Report"
        assert parsed["confidence"] == "High"  # B = High
        assert "healthcare" in parsed["tags"]


# =============================================================================
# CrowdStrike Collector Tests
# =============================================================================


class TestCrowdStrikeCollector:
    """Tests for CrowdStrike collector."""

    def test_source_name(self, mock_credentials):
        """Test source name property."""
        collector = CrowdStrikeCollector(mock_credentials)
        assert collector.source_name == "CrowdStrike"

    def test_parse_actor(self, mock_credentials, crowdstrike_actors_response):
        """Test actor parsing."""
        collector = CrowdStrikeCollector(mock_credentials)
        actor = crowdstrike_actors_response["resources"][0]

        parsed = collector._parse_actor(actor)

        assert parsed["actor_name"] == "FANCY BEAR"
        assert parsed["country"] == "Russia"
        assert "Espionage" in parsed["motivations"]
        assert "Healthcare" in parsed["target_industries"]

    @pytest.mark.asyncio
    async def test_detections_fql_is_bounded_both_ends_with_window(self, mock_credentials):
        """A collection window bounds the detections FQL on BOTH ends (not just 'since')."""

        class _CapturingClient:
            def __init__(self):
                self.params = None

            async def get_raw_response(self, url, headers=None, params=None):
                self.params = params

                class _R:
                    status = 200

                    async def json(self):
                        return {"resources": []}  # empty -> short-circuit, no details call

                return _R()

        window = (datetime(2026, 1, 1), datetime(2026, 3, 31))
        collector = CrowdStrikeCollector(mock_credentials, collection_window=window)
        client = _CapturingClient()
        await collector._fetch_detections(client, "https://api.crowdstrike.com", "tok")

        fql = client.params["filter"]
        assert "created_timestamp:>='2026-01-01T00:00:00Z'" in fql
        assert "created_timestamp:<='2026-03-31T23:59:59Z'" in fql  # end bound present

    @pytest.mark.asyncio
    async def test_spotlight_fql_is_bounded_both_ends_with_window(self, mock_credentials):
        """A collection window bounds the Spotlight FQL on both ends too."""

        class _CapturingClient:
            def __init__(self):
                self.params = None

            async def get_raw_response(self, url, headers=None, params=None):
                self.params = params

                class _R:
                    status = 200

                    async def json(self):
                        return {"resources": []}

                return _R()

        window = (datetime(2026, 1, 1), datetime(2026, 3, 31))
        collector = CrowdStrikeCollector(mock_credentials, collection_window=window)
        client = _CapturingClient()
        await collector._fetch_spotlight_vulnerabilities(client, "https://api.crowdstrike.com", "tok")

        fql = client.params["filter"]
        assert "updated_timestamp:>=" in fql
        assert "updated_timestamp:<='2026-03-31T23:59:59Z'" in fql


# =============================================================================
# Registry Tests
# =============================================================================


class TestRegistry:
    """Tests for collector registry."""

    def test_list_available_collectors(self):
        """Test listing available collectors."""
        collectors = list_available_collectors()
        assert "nvd" in collectors
        assert "intel471" in collectors
        assert "crowdstrike" in collectors

    def test_get_collector(self, mock_credentials):
        """Test getting collector by name."""
        collector = get_collector("nvd", mock_credentials)
        assert collector is not None
        assert collector.source_name == "NVD"

    def test_get_unknown_collector(self, mock_credentials):
        """Test getting unknown collector returns None."""
        collector = get_collector("unknown", mock_credentials)
        assert collector is None


# =============================================================================
# Run tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# =============================================================================
# OSINT full-text extraction (opt-in)
# =============================================================================


class _FakeResp:
    def __init__(self, html: str, status: int = 200):
        self._html = html
        self.status = status

    async def text(self):
        return self._html

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    def __init__(self, html: str, status: int = 200):
        self._html = html
        self._status = status

    def get(self, url, timeout=None):
        return _FakeResp(self._html, self._status)


_ARTICLE_HTML = (
    "<html><body><article><h1>Breach at Acme</h1>"
    "<p>Acme Corp confirmed a ransomware attack by Qilin exploiting CVE-2026-29059. "
    "Attackers exfiltrated 2TB of research data.</p></article></body></html>"
)


class TestOSINTFullText:
    @pytest.mark.asyncio
    async def test_enrich_attaches_capped_full_text(self):
        from src.collectors.osint_collector import OSINTCollector

        collector = OSINTCollector()
        articles = [
            {"title": "a", "url": "https://example.com/a", "summary": "short"},
            {"title": "b", "url": "", "summary": "no url"},  # skipped: no url
        ]
        with patch("src.collectors.osint_collector.enrichment_config") as cfg:
            cfg.enable_osint_fulltext = True
            cfg.osint_fulltext_max_chars = 40
            cfg.osint_fulltext_timeout_seconds = 5
            await collector._enrich_full_text(_FakeSession(_ARTICLE_HTML), articles)

        assert "Acme Corp" in articles[0]["full_text"]
        assert len(articles[0]["full_text"]) <= 40  # capped
        assert "full_text" not in articles[1]  # no url -> untouched

    @pytest.mark.asyncio
    async def test_fetch_full_text_returns_none_on_http_error(self):
        from src.collectors.osint_collector import OSINTCollector
        from src.core.config import enrichment_config

        collector = OSINTCollector()
        import aiohttp

        result = await collector._fetch_full_text(
            _FakeSession("", status=403),
            "https://example.com/x",
            enrichment_config.osint_fulltext_max_chars,
            aiohttp.ClientTimeout(total=5),
        )
        assert result is None


class TestOSINTWindow:
    """The OSINT collector must bound articles by BOTH ends of the collection window.

    Quarterly runs pass an explicit (start, end) for a quarter that has since ended; the
    per-source article cap must fill with IN-quarter articles, not too-new ones a later
    period filter would discard (the bug that made every feed read "0 articles").
    """

    @pytest.mark.asyncio
    async def test_fetch_rss_excludes_out_of_window_entries(self):
        from datetime import UTC, datetime
        from types import SimpleNamespace

        from src.collectors.osint_collector import OSINTCollector

        entries = [
            {"title": "too-new", "link": "u1", "summary": "s", "published": "Sun, 20 Jul 2026 12:00:00 +0000"},
            {"title": "in-window", "link": "u2", "summary": "s", "published": "Fri, 15 May 2026 12:00:00 +0000"},
            {"title": "too-old", "link": "u3", "summary": "s", "published": "Thu, 15 Jan 2026 12:00:00 +0000"},
        ]
        cutoff = datetime(2026, 4, 1, tzinfo=UTC)
        window_end = datetime(2026, 6, 30, 23, 59, 59, tzinfo=UTC)

        collector = OSINTCollector()
        with patch("src.collectors.osint_collector.feedparser.parse") as fp:
            fp.return_value = SimpleNamespace(bozo=False, bozo_exception=None, entries=entries)
            out = await collector._fetch_rss(
                _FakeSession("<rss/>"), "Feed", "https://x/feed", "News", cutoff, 10, window_end
            )
        titles = [a["title"] for a in out]
        assert titles == ["in-window"]  # both the too-new and too-old entries excluded

    def test_quarterly_lookback_default_spans_a_quarter(self):
        # Quarterly runs without an explicit window must look back ~a quarter, not 7 days.
        from src.collectors.osint_collector import _load_osint_config

        cfg = _load_osint_config()
        assert cfg["quarterly_lookback_days"] >= 90
        assert cfg["lookback_days"] <= cfg["quarterly_lookback_days"]

    @pytest.mark.asyncio
    async def test_cap_fills_with_in_window_when_feed_leads_with_too_new(self):
        # A newest-first feed whose head is out-of-window must not exhaust the cap on
        # discarded entries — in-window articles below the head still surface.
        from datetime import UTC, datetime
        from types import SimpleNamespace

        from src.collectors.osint_collector import OSINTCollector

        entries = [{"title": f"jul-{d}", "link": f"n{d}", "summary": "s",
                    "published": f"{d:02d} Jul 2026 12:00:00 +0000"} for d in range(1, 6)]
        entries.append({"title": "in-window", "link": "w", "summary": "s",
                        "published": "15 May 2026 12:00:00 +0000"})
        cutoff = datetime(2026, 4, 1, tzinfo=UTC)
        window_end = datetime(2026, 6, 30, 23, 59, 59, tzinfo=UTC)

        collector = OSINTCollector()
        with patch("src.collectors.osint_collector.feedparser.parse") as fp:
            fp.return_value = SimpleNamespace(bozo=False, bozo_exception=None, entries=entries)
            out = await collector._fetch_rss(
                _FakeSession("<rss/>"), "Feed", "https://x/feed", "News", cutoff, 2, window_end
            )
        assert [a["title"] for a in out] == ["in-window"]


class TestIlluminaSecFilings:
    """The company scraper must surface MATERIAL filings (10-K/10-Q/8-K), not the
    insider-trade Form 4/144 noise that dominates the newest-first EDGAR feed."""

    def _data(self):
        return {
            "filings": {
                "recent": {
                    "form": ["4", "4", "8-K", "144", "10-Q", "SC 13G/A", "10-K"],
                    "filingDate": [
                        "2026-07-02",
                        "2026-07-01",
                        "2026-06-28",
                        "2026-06-25",
                        "2026-06-20",
                        "2026-05-20",
                        "2026-02-10",
                    ],
                    "primaryDocDescription": ["", "", "Current report", "", "Quarterly report", "", "Annual report"],
                    "primaryDocument": ["form4.xml", "form4.xml", "d8k.htm", "p.xml", "d10q.htm", "sc.htm", "d10k.htm"],
                    "accessionNumber": ["a-1", "a-2", "a-3", "a-4", "a-5", "a-6", "a-7"],
                    "items": ["", "", "1.05,8.01", "", "", "", ""],
                }
            }
        }

    def test_filters_out_insider_and_ownership_noise(self):
        from src.collectors.illumina_osint_collector import IlluminaOSINTCollector

        out = IlluminaOSINTCollector._format_sec_filings(self._data(), cik="1110803")
        # Material forms are present...
        assert "10-Q" in out and "10-K" in out and "8-K" in out
        # ...and the insider-trade / ownership forms are gone.
        assert "Form 4" not in out and "144" not in out and "13G" not in out

    def test_flags_cyber_incident_8k_item(self):
        from src.collectors.illumina_osint_collector import IlluminaOSINTCollector

        out = IlluminaOSINTCollector._format_sec_filings(self._data(), cik="1110803")
        assert "1.05 Material Cybersecurity Incident" in out

    def test_no_material_filings_returns_message(self):
        from src.collectors.illumina_osint_collector import IlluminaOSINTCollector

        data = {"filings": {"recent": {"form": ["4", "144"], "filingDate": ["2026-07-02", "2026-07-01"]}}}
        out = IlluminaOSINTCollector._format_sec_filings(data, cik="1110803")
        assert "No recent material filings" in out


class TestIlluminaIRFeed:
    """The IR press-release feed reader should parse RSS/Atom and JSON shapes and
    drop items outside the lookback window."""

    _CUTOFF = datetime(2026, 4, 24, tzinfo=UTC)

    def test_json_feed_standard_shape_and_lookback(self):
        import json

        from src.collectors.illumina_osint_collector import IlluminaOSINTCollector

        body = json.dumps(
            {
                "items": [
                    {"title": "Illumina expands Billion Cell Atlas program", "url": "https://x/1",
                     "date_published": "2026-07-02T00:00:00Z"},
                    {"title": "Old release from January 2026", "url": "https://x/old",
                     "date_published": "2026-01-05T00:00:00Z"},  # outside window -> dropped
                ]
            }
        )
        out = IlluminaOSINTCollector._format_json_feed(body, self._CUTOFF)
        assert "Billion Cell Atlas" in out and "https://x/1" in out
        assert "January 2026" not in out

    def test_json_feed_ir_api_shape_and_rfc_date(self):
        import json

        from src.collectors.illumina_osint_collector import IlluminaOSINTCollector

        body = json.dumps(
            {
                "GetPressReleaseListResult": [
                    {"Headline": "Illumina appoints new Chief Legal Officer", "LinkToDetailPage": "https://x/2",
                     "PressReleaseDate": "Tue, 24 Jun 2026 08:00:00 GMT"}
                ]
            }
        )
        out = IlluminaOSINTCollector._format_json_feed(body, self._CUTOFF)
        assert "Chief Legal Officer" in out and "2026-06-24" in out

    def test_rss_via_feedparser(self):
        from src.collectors.illumina_osint_collector import IlluminaOSINTCollector

        rss = (
            b"<?xml version='1.0'?><rss version='2.0'><channel>"
            b"<item><title>Illumina Q2 2026 Financial Results</title>"
            b"<link>https://investor.illumina.com/news/q2-2026</link>"
            b"<pubDate>Wed, 15 Jul 2026 12:00:00 GMT</pubDate></item>"
            b"<item><title>Stale item from 2025</title>"
            b"<link>https://x/stale</link>"
            b"<pubDate>Wed, 15 Jan 2025 12:00:00 GMT</pubDate></item>"
            b"</channel></rss>"
        )
        out = IlluminaOSINTCollector._format_feed_entries(rss, self._CUTOFF)
        assert "Q2 2026 Financial Results" in out
        assert "Stale item" not in out


# =============================================================================
# Explicit collection window (historical backfill plumbing)
# =============================================================================


class TestCollectionWindow:
    """An explicit collection_window overrides the trailing now-lookback range so
    Intel471/NVD can query a specific past quarter for prior-quarter backfill."""

    def test_window_overrides_trailing_range(self, mock_credentials):
        window = (datetime(2026, 1, 1), datetime(2026, 3, 31))
        collector = get_collector("nvd", mock_credentials, collection_window=window)
        assert collector.get_date_range() == window

    def test_no_window_uses_trailing_range(self, mock_credentials):
        collector = get_collector("nvd", mock_credentials)
        start, end = collector.get_date_range()
        assert start < end  # trailing now-lookback -> now

    def test_registry_threads_window_to_all_collectors(self, mock_credentials):
        window = (datetime(2026, 1, 1), datetime(2026, 3, 31))
        for name in ("nvd", "intel471", "crowdstrike", "news_search"):
            c = get_collector(name, mock_credentials, report_type="quarterly", collection_window=window)
            assert c.collection_window == window


# =============================================================================
# GDELT news-search collector (date-bounded archive for backfill)
# =============================================================================


class TestNewsSearchCollector:
    def test_build_params_formats_datetimes(self):
        from src.collectors.news_search_collector import build_gdelt_params

        params = build_gdelt_params("biotech breach", datetime(2026, 1, 1, 0, 0, 0), datetime(2026, 3, 31, 23, 59, 59), 40)
        assert params["startdatetime"] == "20260101000000"
        assert params["enddatetime"] == "20260331235959"
        assert params["maxrecords"] == "40"
        assert params["mode"] == "ArtList"
        assert params["format"] == "json"

    def test_parse_response_maps_to_osint_schema(self):
        from src.collectors.news_search_collector import parse_gdelt_response

        payload = {
            "articles": [
                {"title": "Genomics firm hit by ransomware CVE-2026-1234", "url": "https://n/1",
                 "seendate": "20260115T120000Z", "domain": "example.com"},
                {"title": "", "url": "https://n/bad"},  # no title -> dropped
                {"url": "https://n/notitle", "seendate": "20260201T000000Z"},  # dropped
            ]
        }
        out = parse_gdelt_response(payload)
        assert len(out) == 1
        art = out[0]
        assert art["url"] == "https://n/1"
        assert art["type"] == "osint_article"
        assert art["published_date"].startswith("2026-01-15")
        assert "CVE-2026-1234" in art["cves_mentioned"]

    def test_parse_response_handles_empty(self):
        from src.collectors.news_search_collector import parse_gdelt_response

        assert parse_gdelt_response({}) == []
        assert parse_gdelt_response({"articles": []}) == []

    def test_loads_tolerates_non_json(self):
        from src.collectors.news_search_collector import NewsSearchCollector

        assert NewsSearchCollector._loads("") == {"articles": []}
        assert NewsSearchCollector._loads("<html>error</html>") == {"articles": []}

    def test_news_search_registered(self):
        assert "news_search" in list_available_collectors()


# =============================================================================
# Breach-dataset collectors (VCDB / HHS / HIBP) — parsers
# =============================================================================


class TestVCDBParser:
    def test_parses_veris_incident_and_filters_industry(self):
        from src.collectors.vcdb_collector import parse_vcdb

        payload = [
            {
                "victim": {"victim_id": "Acme Health", "industry": "622"},  # health care -> kept
                "timeline": {"incident": {"year": 2026, "month": 4, "day": 12}},
                "attribute": {"confidentiality": {"data_total": 250000}},
                "action": {"malware": {"variety": ["Ransomware"]}},
                "summary": "Ransomware at Acme Health",
            },
            {
                "victim": {"victim_id": "Retailer", "industry": "44"},  # retail -> filtered out
                "timeline": {"incident": {"year": 2026, "month": 5}},
                "action": {"hacking": {"variety": ["SQLi"]}},
            },
        ]
        out = parse_vcdb(payload, naics_prefixes=("31", "32", "33", "54", "62"))
        assert len(out) == 1
        r = out[0]
        assert r["organization"] == "Acme Health"
        assert r["date"] == "2026-04-12"
        assert r["incident_type"] == "Ransomware"
        assert r["records_exposed"] == 250000
        assert r["sector"] == "Healthcare"  # NAICS 622 -> healthcare (weights the $ estimate)
        assert r["source"] == "VCDB"

    def test_no_industry_filter_keeps_all(self):
        from src.collectors.vcdb_collector import parse_vcdb

        payload = [
            {"victim": {"victim_id": "X", "industry": "44"}, "timeline": {"incident": {"year": 2026, "month": 6}},
             "action": {"error": {}}}
        ]
        out = parse_vcdb(payload, naics_prefixes=())
        assert len(out) == 1
        assert out[0]["incident_type"] == "Data Exposure"


class TestHHSParser:
    def test_parses_csv_rows(self):
        from src.collectors.hhs_breach_collector import parse_hhs_csv

        csv_text = (
            "Name of Covered Entity,State,Covered Entity Type,Individuals Affected,"
            "Breach Submission Date,Type of Breach\n"
            "Covenant Health,TN,Healthcare Provider,\"1,200,000\",04/15/2026,Hacking/IT Incident - Ransomware\n"
            "Mercy Clinic,MO,Healthcare Provider,45000,05/03/2026,Unauthorized Access/Disclosure\n"
        )
        out = parse_hhs_csv(csv_text)
        assert len(out) == 2
        assert out[0]["organization"] == "Covenant Health"
        assert out[0]["date"] == "2026-04-15"
        assert out[0]["incident_type"] == "Ransomware"
        assert out[0]["records_exposed"] == 1200000
        assert out[0]["sector"] == "Healthcare"
        assert out[1]["incident_type"] == "Unauthorized Access"

    def test_empty_csv_is_empty(self):
        from src.collectors.hhs_breach_collector import parse_hhs_csv

        assert parse_hhs_csv("") == []

    def test_parses_bom_prefixed_header(self):
        # An Excel-friendly export prefixes a UTF-8 BOM; the header column must still resolve.
        from src.collectors.hhs_breach_collector import parse_hhs_csv

        csv_text = (
            "﻿Name of Covered Entity,State,Individuals Affected,"
            "Breach Submission Date,Type of Breach\n"
            "Acme Health,CA,12345,01/15/2026,Hacking/IT Incident\n"
        )
        out = parse_hhs_csv(csv_text)
        assert len(out) == 1
        assert out[0]["organization"] == "Acme Health"
        assert out[0]["records_exposed"] == 12345

    def test_parses_reworded_header_case_and_spacing(self):
        # The portal has varied header casing/spacing; a substring/normalized match must hold.
        from src.collectors.hhs_breach_collector import parse_hhs_csv

        csv_text = (
            "NAME OF COVERED ENTITY ,State, Individuals  Affected ,"
            " Breach Submission Date ,Type of Breach\n"
            "Beta Labs,NY,7,02/03/2026,Ransomware\n"
        )
        out = parse_hhs_csv(csv_text)
        assert len(out) == 1
        assert out[0]["organization"] == "Beta Labs"
        assert out[0]["incident_type"] == "Ransomware"
        assert out[0]["records_exposed"] == 7


class TestHHSDownloadDecode:
    """The browser download may arrive as UTF-8/UTF-8-BOM/UTF-16/cp1252 — all must decode
    to text the CSV sniff accepts (the prior utf-8-only read mangled the non-utf-8 variants)."""

    _CSV = (
        "Name of Covered Entity,State,Individuals Affected,Breach Submission Date,Type of Breach\n"
        "Acme Health,CA,12345,01/15/2026,Hacking/IT Incident\n"
    )

    @pytest.mark.parametrize("enc", ["utf-8", "utf-8-sig", "utf-16", "cp1252", "latin-1"])
    def test_decodes_and_sniffs(self, enc):
        from src.collectors.hhs_fetch import looks_like_hhs_csv
        from src.collectors.hhs_playwright import decode_csv_bytes

        text = decode_csv_bytes(self._CSV.encode(enc))
        assert looks_like_hhs_csv(text), f"{enc} decode failed the sniff: {text[:80]!r}"

    def test_decode_never_raises_on_garbage(self):
        from src.collectors.hhs_playwright import decode_csv_bytes

        # Invalid-in-every-strict-encoding bytes must still return a str (lossy fallback).
        assert isinstance(decode_csv_bytes(b"\xff\xfe\x00\x80\x81\xffabc"), str)


class TestHHSBrowserFetch:
    @pytest.mark.asyncio
    async def test_returns_none_when_playwright_absent(self, monkeypatch):
        # The browser export is optional: with Playwright not installed it must degrade to
        # None (collector then yields an empty result), never crash.
        import builtins

        from src.collectors.hhs_playwright import fetch_hhs_csv_via_browser

        real_import = builtins.__import__

        def _blocked(name, *a, **k):
            if name == "playwright" or name.startswith("playwright."):
                raise ImportError("No module named 'playwright'")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", _blocked)
        assert await fetch_hhs_csv_via_browser("https://ocrportal.hhs.gov/x", headless=True) is None


class TestHHSPortalFetch:
    """The JSF portal export flow: ViewState/control extraction + CSV sniff (offline)."""

    _HTML = (
        '<html><body><form id="ristr" action="/ocr/breach/breach_report.jsf" method="post">'
        '<input type="hidden" name="ristr" value="ristr" />'
        '<input type="hidden" name="javax.faces.ViewState" value="VS-TOKEN-123" />'
        '<button id="ristr:csvExport" name="ristr:csvExport" value="CSV">Export CSV</button>'
        "</form></body></html>"
    )

    def test_extract_viewstate(self):
        from src.collectors.hhs_fetch import extract_viewstate

        assert extract_viewstate(self._HTML) == "VS-TOKEN-123"
        assert extract_viewstate("<html>no jsf here</html>") is None

    def test_extract_hidden_fields(self):
        from src.collectors.hhs_fetch import extract_hidden_fields

        fields = extract_hidden_fields(self._HTML)
        assert fields["ristr"] == "ristr"
        assert fields["javax.faces.ViewState"] == "VS-TOKEN-123"

    def test_extract_form_action_resolves_relative(self):
        from src.collectors.hhs_fetch import extract_form_action

        action = extract_form_action(self._HTML, "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf")
        assert action == "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"

    def test_find_export_controls(self):
        from src.collectors.hhs_fetch import find_export_controls

        assert "ristr:csvExport" in find_export_controls(self._HTML)
        assert find_export_controls("<button id='save'>Save</button>") == []

    def test_looks_like_hhs_csv(self):
        from src.collectors.hhs_fetch import looks_like_hhs_csv

        assert looks_like_hhs_csv("Name of Covered Entity,State,Individuals Affected\nAcme,TN,500")
        assert not looks_like_hhs_csv("<html><body>portal page</body></html>")
        assert not looks_like_hhs_csv("")


class TestHIBPParser:
    def test_parses_breaches(self):
        from src.collectors.hibp_breach_collector import parse_hibp

        payload = [
            {"Name": "Acme", "Title": "Acme", "Domain": "acme.com", "BreachDate": "2026-04-20",
             "PwnCount": 800000, "DataClasses": ["Email addresses", "Passwords"], "Description": "creds leaked"},
            {"Name": "NoDate", "BreachDate": "", "PwnCount": 1},  # dropped: no date
        ]
        out = parse_hibp(payload)
        assert len(out) == 1
        r = out[0]
        assert r["organization"] == "Acme"
        assert r["date"] == "2026-04-20"
        assert r["records_exposed"] == 800000
        assert r["incident_type"] == "Data Exposure"
        assert r["sector"] == "Technology"
        assert r["url"] == "https://acme.com"

    def test_ransomware_from_description(self):
        from src.collectors.hibp_breach_collector import parse_hibp

        out = parse_hibp([{"Name": "X", "BreachDate": "2026-04-01", "PwnCount": 10,
                           "Description": "data leaked following a ransom demand"}])
        assert out[0]["incident_type"] == "Ransomware"


class TestBreachCollectorsRegistered:
    def test_registered(self):
        names = list_available_collectors()
        assert {"vcdb", "hhs_breach", "hibp_breach"} <= set(names)

    def test_enabled_only_for_quarterly(self, mock_credentials):
        from src.collectors.vcdb_collector import VCDBCollector

        assert VCDBCollector(mock_credentials, report_type="quarterly").enabled is True
        assert VCDBCollector(mock_credentials, report_type="weekly").enabled is False

    @pytest.mark.asyncio
    async def test_dataset_source_reads_local_file(self, tmp_path):
        from src.collectors.dataset_source import fetch_dataset_text

        p = tmp_path / "vcdb.json"
        p.write_text('{"ok": true}', encoding="utf-8")
        # A local path is read directly (no network) — the reliable way to pin a dataset.
        assert await fetch_dataset_text(str(p), headers={}) == '{"ok": true}'
        assert await fetch_dataset_text(f"file://{p}", headers={}) == '{"ok": true}'

    @pytest.mark.asyncio
    async def test_dataset_source_missing_local_file_returns_none(self, tmp_path):
        from src.collectors.dataset_source import fetch_dataset_text

        # A non-existent local path is treated as "no data", not a crash.
        assert await fetch_dataset_text(str(tmp_path / "nope.json"), headers={}) is None

    def test_hibp_off_by_default_on_when_flag_set(self, mock_credentials, monkeypatch):
        from types import SimpleNamespace

        from src.collectors import hibp_breach_collector as mod
        from src.collectors.hibp_breach_collector import HIBPBreachCollector

        # Off by default (not an industry peer source; also mega-breaches dominate).
        assert HIBPBreachCollector(mock_credentials, report_type="quarterly").enabled is False
        # On when the operator opts in (collector_config is a frozen dataclass, so swap the ref).
        monkeypatch.setattr(mod, "collector_config", SimpleNamespace(breach_include_hibp=True))
        assert HIBPBreachCollector(mock_credentials, report_type="quarterly").enabled is True
