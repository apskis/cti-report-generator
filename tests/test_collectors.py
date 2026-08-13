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


class TestWaybackHelpers:
    """Pure Wayback CDX/snapshot helpers (offline)."""

    def test_build_cdx_url(self):
        from datetime import datetime

        from src.collectors.wayback import build_cdx_url

        u = build_cdx_url("https://www.bleepingcomputer.com/feed/", datetime(2026, 4, 1), datetime(2026, 6, 30))
        assert "from=20260401" in u and "to=20260630" in u
        assert "collapse=timestamp%3A8" in u and "filter=statuscode%3A200" in u

    def test_parse_cdx_json(self):
        from src.collectors.wayback import parse_cdx_json

        txt = (
            '[["timestamp","original"],'
            '["20260415120000","https://www.bleepingcomputer.com/feed/"],'
            '["20260501000000","https://www.bleepingcomputer.com/feed/"]]'
        )
        rows = parse_cdx_json(txt)
        assert rows == [
            ("20260415120000", "https://www.bleepingcomputer.com/feed/"),
            ("20260501000000", "https://www.bleepingcomputer.com/feed/"),
        ]
        # Malformed / header-only / empty all yield []
        assert parse_cdx_json("") == []
        assert parse_cdx_json('[["timestamp","original"]]') == []
        assert parse_cdx_json("not json") == []

    def test_sample_snapshots_even_spread_keeps_ends(self):
        from src.collectors.wayback import sample_snapshots

        rows = [(str(i), "u") for i in range(20)]
        s = sample_snapshots(rows, 6)
        assert len(s) == 6 and s[0] == rows[0] and s[-1] == rows[19]
        assert sample_snapshots(rows, 1) == [rows[10]]
        assert sample_snapshots(rows[:3], 6) == rows[:3]  # fewer than max -> all
        assert sample_snapshots([], 6) == []
        assert sample_snapshots(rows, 0) == []

    def test_snapshot_raw_url_uses_id_suffix(self):
        from src.collectors.wayback import snapshot_raw_url

        assert snapshot_raw_url("20260415120000", "https://x/feed/") == (
            "https://web.archive.org/web/20260415120000id_/https://x/feed/"
        )

    @pytest.mark.asyncio
    async def test_fetch_archived_feed_bodies_orchestration(self):
        from datetime import datetime

        from src.collectors.wayback import fetch_archived_feed_bodies

        cdx_json = (
            '[["timestamp","original"],'
            '["20260415120000","https://x/feed/"],'
            '["20260515120000","https://x/feed/"]]'
        )

        class _DispatchResp:
            def __init__(self, url):
                self.status = 200
                self._url = url

            async def text(self):
                if "/cdx/" in self._url:
                    return cdx_json
                assert "id_/" in self._url  # raw snapshot form, no toolbar
                return f"<rss>{self._url}</rss>"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        class _DispatchSession:
            def get(self, url, timeout=None, headers=None):
                return _DispatchResp(url)

        bodies = await fetch_archived_feed_bodies(
            _DispatchSession(), "https://x/feed/", datetime(2026, 4, 1), datetime(2026, 6, 30), max_snapshots=6
        )
        assert len(bodies) == 2
        assert all(b.startswith("<rss>") for b in bodies)

    @pytest.mark.asyncio
    async def test_wayback_reachable_detects_ok_and_blocks(self):
        from src.collectors.wayback import wayback_reachable

        class _Resp:
            def __init__(self, status, body):
                self.status, self._body = status, body

            async def text(self):
                return self._body

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        class _Sess:
            def __init__(self, status, body):
                self._status, self._body = status, body

            def get(self, url, timeout=None):
                return _Resp(self._status, self._body)

        ok, _ = await wayback_reachable(_Sess(200, '[["timestamp","original"]]'))
        assert ok is True
        # A proxy/WAF block: 498 + nginx HTML page.
        ok, reason = await wayback_reachable(_Sess(498, "<html><title>404 Not Found</title></html>"))
        assert ok is False and "498" in reason
        # A 200 that is NOT the expected JSON array (block page served with 200).
        ok, reason = await wayback_reachable(_Sess(200, "<html>blocked</html>"))
        assert ok is False and "non-JSON" in reason

    @pytest.mark.asyncio
    async def test_fetch_archived_feed_bodies_empty_on_cdx_error(self):
        from datetime import datetime

        from src.collectors.wayback import fetch_archived_feed_bodies

        class _ErrResp:
            status = 503

            async def text(self):
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        class _ErrSession:
            def get(self, url, timeout=None, headers=None):
                return _ErrResp()

        out = await fetch_archived_feed_bodies(
            _ErrSession(), "https://x/feed/", datetime(2026, 4, 1), datetime(2026, 6, 30)
        )
        assert out == []


class TestOSINTArchiveMerge:
    """_fetch_rss merges live + Wayback snapshot bodies, deduped and window-filtered.

    feedparser.parse is patched per-body (bodies are opaque marker strings) so the test is
    deterministic without depending on the real parser.
    """

    @staticmethod
    def _entry(title, link, date):
        return {"title": title, "link": link, "summary": "", "published": date}

    def _parser(self, mapping):
        from types import SimpleNamespace

        def _parse(body):
            return SimpleNamespace(bozo=False, bozo_exception=None, entries=mapping.get(body, []))

        return _parse

    @pytest.mark.asyncio
    async def test_archive_recovers_in_window_articles_and_dedupes(self):
        from datetime import UTC, datetime

        from src.collectors.osint_collector import OSINTCollector

        live, snap1, snap2 = "LIVE", "SNAP1", "SNAP2"
        mapping = {
            # Live feed holds only a too-new (out-of-window) article.
            live: [self._entry("Live July", "https://x/live-jul", "Mon, 20 Jul 2026 12:00:00 +0000")],
            # Two snapshots overlapping on "Shared May" plus one unique each.
            snap1: [
                self._entry("Shared May", "https://x/shared-may", "Fri, 15 May 2026 12:00:00 +0000"),
                self._entry("April One", "https://x/apr-1", "Wed, 15 Apr 2026 12:00:00 +0000"),
            ],
            snap2: [
                self._entry("Shared May", "https://x/shared-may", "Fri, 15 May 2026 12:00:00 +0000"),
                self._entry("June One", "https://x/jun-1", "Mon, 15 Jun 2026 12:00:00 +0000"),
            ],
        }
        cutoff = datetime(2026, 4, 1, tzinfo=UTC)
        window_end = datetime(2026, 6, 30, 23, 59, 59, tzinfo=UTC)

        collector = OSINTCollector()
        with (
            patch("src.collectors.wayback.fetch_archived_feed_bodies", new=AsyncMock(return_value=[snap1, snap2])),
            patch("src.collectors.osint_collector.feedparser.parse", side_effect=self._parser(mapping)),
        ):
            out = await collector._fetch_rss(
                _FakeSession(live), "BleepingComputer", "https://x/feed", "News",
                cutoff, 10, window_end, use_archive=True, max_snapshots=6,
            )
        titles = [a["title"] for a in out]
        # July excluded (out of window); the shared May article deduped to one; freshest first.
        assert titles == ["June One", "Shared May", "April One"]

    @pytest.mark.asyncio
    async def test_no_archive_call_when_use_archive_false(self):
        from datetime import UTC, datetime

        from src.collectors.osint_collector import OSINTCollector

        live = "LIVE"
        mapping = {live: [self._entry("In May", "https://x/may", "Fri, 15 May 2026 12:00:00 +0000")]}
        cutoff = datetime(2026, 4, 1, tzinfo=UTC)
        window_end = datetime(2026, 6, 30, 23, 59, 59, tzinfo=UTC)

        collector = OSINTCollector()
        spy = AsyncMock(return_value=[])
        with (
            patch("src.collectors.wayback.fetch_archived_feed_bodies", new=spy),
            patch("src.collectors.osint_collector.feedparser.parse", side_effect=self._parser(mapping)),
        ):
            out = await collector._fetch_rss(
                _FakeSession(live), "Feed", "https://x/feed", "News",
                cutoff, 10, window_end, use_archive=False,
            )
        spy.assert_not_awaited()
        assert [a["title"] for a in out] == ["In May"]


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

class TestICSAdvisoryCollector:
    """Tests for the ICS/OT advisory collector (RapidAPI ICS[AP] API)."""

    @pytest.fixture
    def ics_credentials(self):
        return {"rapidapi_ics_key": "test-rapidapi-key"}

    @pytest.fixture
    def ics_api_response(self):
        """Sample response mirroring the ICS Advisory Project (CISA ICS) schema."""
        return [
            {
                "ICS-CERT_Number": "ICSA-26-100-01",
                "ICS-CERT_Advisory_Title": "Example PLC Stack Overflow",
                "Vendor": "ExampleVendor",
                "Product": "ExamplePLC 3000",
                "Products_Affected": "ExamplePLC 3000 firmware < 2.1",
                "CVSS_Severity": "Critical",
                "Cumulative_CVSS": "9.8",
                "CVE": "CVE-2026-1111, CVE-2026-2222",
                "Original_Release_Date": "2026-04-10",
                "Last_Updated": "2026-04-10",
            },
            {
                "advisory_id": "ICSMA-26-101-02",
                "title": "Example Infusion Pump Auth Bypass",
                "vendor": "MedVendor",
                "product": "PumpOS",
                "severity": "high",
                "cvss": 7.5,
                "cves": ["CVE-2026-3333"],
                "release_date": "2026-04-11",
            },
        ]

    def test_source_name(self, ics_credentials):
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        assert ICSAdvisoryCollector(ics_credentials).source_name == "ICS-Advisory"

    def test_enabled_requires_key(self):
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        assert ICSAdvisoryCollector({"rapidapi_ics_key": "k"}).enabled is True
        assert ICSAdvisoryCollector({}).enabled is False

    def test_registered(self):
        assert "ics_advisory" in list_available_collectors()
        collector = get_collector("ics_advisory", {"rapidapi_ics_key": "k"})
        assert collector is not None
        assert collector.source_name == "ICS-Advisory"

    def test_extract_records_envelopes(self, ics_credentials):
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        c = ICSAdvisoryCollector(ics_credentials)
        assert c._extract_records([{"a": 1}]) == [{"a": 1}]
        # "result" is the confirmed live envelope key ({"error": false, "result": [...]}).
        assert c._extract_records({"error": False, "result": [{"a": 1}]}) == [{"a": 1}]
        assert c._extract_records({"data": [{"a": 1}]}) == [{"a": 1}]
        assert c._extract_records({"advisories": [{"b": 2}]}) == [{"b": 2}]
        assert c._extract_records({"nope": 1}) == []

    @pytest.mark.asyncio
    async def test_collect_dedups_live_envelope(self, ics_credentials):
        """Live free-tier payload: 'result' envelope with duplicate rows -> unique advisories."""
        from src.collectors import ics_advisory_collector as mod
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        # Shape and duplicates mirror the real ICS[AP] BASIC-tier response.
        live = {
            "error": False,
            "result": [
                {"Last_Updated": "2026-07-02T00:00:00.000Z", "ICS-CERT_Number": "ICSA-26-183-03",
                 "ICS-CERT_Advisory_Title": "Gardyn IoT Hub", "CVSS_Severity": "Critical"},
                {"Last_Updated": "2026-07-02T00:00:00.000Z", "ICS-CERT_Number": "ICSA-26-183-03",
                 "ICS-CERT_Advisory_Title": "Gardyn IoT Hub", "CVSS_Severity": "Critical"},
                {"Last_Updated": "2026-07-02T00:00:00.000Z", "ICS-CERT_Number": "ICSA-26-183-01",
                 "ICS-CERT_Advisory_Title": "ST Engineering iDirect", "CVSS_Severity": "High"},
            ],
            "message": "You are using the BASIC free tier...",
        }

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url, headers=None, params=None):
                # Latest returns the list; the per-advisory detail endpoint has nothing
                # extra here (this test focuses on dedup, not enrichment).
                return live if url.endswith("/latest") else {"result": []}

        collector = ICSAdvisoryCollector(
            ics_credentials, collection_window=(datetime(2026, 6, 1), datetime(2026, 7, 31))
        )
        with patch.object(mod, "HTTPClient", lambda *a, **k: _FakeClient()):
            result = await collector.collect()

        assert result.success is True
        # 3 raw rows (one duplicate) -> 2 unique advisories, and the free-tier
        # date field (Last_Updated only) is used for the window check.
        assert result.record_count == 2
        assert {a["advisory_id"] for a in result.data} == {"ICSA-26-183-03", "ICSA-26-183-01"}

    def test_parse_advisory_primary_and_alt_keys(self, ics_credentials, ics_api_response):
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        c = ICSAdvisoryCollector(ics_credentials)

        a0 = c._parse_advisory(ics_api_response[0])
        assert a0["advisory_id"] == "ICSA-26-100-01"
        assert a0["vendor"] == "ExampleVendor"
        assert a0["severity"] == "CRITICAL"
        assert a0["cvss"] == 9.8
        assert a0["cves"] == ["CVE-2026-1111", "CVE-2026-2222"]
        # URL is synthesized from the advisory id when absent.
        assert a0["advisory_id"] in a0["url"]

        # Second record uses the lower-case alternate field spellings.
        a1 = c._parse_advisory(ics_api_response[1])
        assert a1["advisory_id"] == "ICSMA-26-101-02"
        assert a1["cves"] == ["CVE-2026-3333"]

    def test_parse_advisory_skips_empty(self, ics_credentials):
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        assert ICSAdvisoryCollector(ics_credentials)._parse_advisory({"Vendor": "X"}) is None

    def test_within_window_filters_by_date(self, ics_credentials):
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        c = ICSAdvisoryCollector(ics_credentials)
        start, end = datetime(2026, 4, 1), datetime(2026, 4, 30)
        assert c._within_window({"released": "2026-04-15"}, start, end) is True
        assert c._within_window({"released": "2026-01-15"}, start, end) is False
        # Undated advisories are kept rather than silently dropped.
        assert c._within_window({"released": ""}, start, end) is True

    @pytest.mark.asyncio
    async def test_collect_disabled_without_key(self):
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        result = await ICSAdvisoryCollector({}).collect()
        assert result.success is True
        assert result.record_count == 0

    @pytest.mark.asyncio
    async def test_collect_parses_and_windows(self, ics_credentials, ics_api_response):
        from src.collectors import ics_advisory_collector as mod
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url, headers=None, params=None):
                # Assert RapidAPI auth headers are set correctly.
                assert headers["x-rapidapi-key"] == "test-rapidapi-key"
                assert headers["x-rapidapi-host"] == "ics-ap-apis.p.rapidapi.com"
                # Latest returns the list; detail endpoint adds nothing in this test.
                return ics_api_response if url.endswith("/latest") else {"result": []}

        collector = ICSAdvisoryCollector(ics_credentials, collection_window=(datetime(2026, 4, 1), datetime(2026, 4, 30)))
        with patch.object(mod, "HTTPClient", lambda *a, **k: _FakeClient()):
            result = await collector.collect()

        assert result.success is True
        assert result.record_count == 2
        ids = {a["advisory_id"] for a in result.data}
        assert ids == {"ICSA-26-100-01", "ICSMA-26-101-02"}

    def test_parse_cve_number_field(self, ics_credentials):
        """The detail endpoint returns CVEs under 'CVE_Number' (a list)."""
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        c = ICSAdvisoryCollector(ics_credentials)
        a = c._parse_advisory(
            {"ICS-CERT_Number": "ICSA-26-1", "ICS-CERT_Advisory_Title": "X",
             "CVE_Number": ["CVE-2026-1", "CVE-2026-2"]}
        )
        assert a["cves"] == ["CVE-2026-1", "CVE-2026-2"]

    @pytest.mark.asyncio
    async def test_collect_enriches_from_detail_endpoint(self, ics_credentials):
        """The summary list is enriched per-advisory with vendor/product/CVEs/CVSS."""
        from src.collectors import ics_advisory_collector as mod
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        # Summary (list endpoint, free-tier fields only).
        summary = {"error": False, "result": [
            {"Last_Updated": "2026-07-02T00:00:00.000Z", "ICS-CERT_Number": "ICSA-26-183-03",
             "ICS-CERT_Advisory_Title": "Gardyn IoT Hub", "CVSS_Severity": "Critical"},
        ]}
        # Detail (entry endpoint) — full record, real live shape.
        detail = {"error": False, "result": [
            {"ICS-CERT_Number": "ICSA-26-183-03", "ICS-CERT_Advisory_Title": "Gardyn IoT Hub",
             "Vendor": "Gardyn", "Product": "Gardyn IoT Hub",
             "Products_Affected": "Home Firmware | Cloud API <2.12.2026",
             "CVE_Number": ["CVE-2026-13768", "CVE-2026-55726"], "Cumulative_CVSS": 10,
             "CVSS_Severity": "Critical", "Last_Updated": "2026-07-02T00:00:00.000Z",
             "hyperlink": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-183-03"},
        ]}

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url, headers=None, params=None):
                return summary if url.endswith("/latest") else detail

        collector = ICSAdvisoryCollector(
            ics_credentials, collection_window=(datetime(2026, 6, 1), datetime(2026, 7, 31))
        )
        with patch.object(mod, "HTTPClient", lambda *a, **k: _FakeClient()):
            result = await collector.collect()

        assert result.record_count == 1
        a = result.data[0]
        assert a["vendor"] == "Gardyn"
        assert a["cvss"] == 10
        assert a["cves"] == ["CVE-2026-13768", "CVE-2026-55726"]
        assert "cisa.gov" in a["url"]


class TestICSAdvisoryWiring:
    """Regression tests locking the OT pipeline wiring.

    The weekly handler (function_app.py) keys off the collector's ``source_name``
    literal (``"ICS-Advisory"``) to route advisories into ``analysis["ot_advisories"]``,
    which the report's OT section renders. A rename of ``source_name`` (or the handler
    key) would silently drop the OT data with no error — these tests fail loudly first.
    """

    # The single source of truth the whole OT path agrees on.
    SOURCE_KEY = "ICS-Advisory"

    def test_source_name_is_stable(self):
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        # If this changes, function_app.py's data_by_source.get(...) key must change too.
        assert ICSAdvisoryCollector({}).source_name == self.SOURCE_KEY

    @pytest.mark.asyncio
    async def test_collect_all_keys_result_by_source_name(self):
        """collect_all must expose the ICS result under exactly SOURCE_KEY."""
        from src.collectors import ics_advisory_collector as mod
        from src.collectors.registry import collect_all

        sample = [
            {
                "ICS-CERT_Number": "ICSA-26-100-01",
                "ICS-CERT_Advisory_Title": "PLC overflow",
                "Vendor": "ExampleVendor",
                "Product": "PLC 3000",
                "CVSS_Severity": "Critical",
                "Cumulative_CVSS": "9.8",
                "CVE": "CVE-2026-1111",
                "Original_Release_Date": "2026-08-04",
            }
        ]

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url, headers=None, params=None):
                return sample

        with patch.object(mod, "HTTPClient", lambda *a, **k: _FakeClient()):
            results = await collect_all(
                {"rapidapi_ics_key": "k"},
                report_type="weekly",
                collection_window=(datetime(2026, 8, 1), datetime(2026, 8, 5)),
                collector_names=["ics_advisory"],
            )

        assert self.SOURCE_KEY in results
        assert results[self.SOURCE_KEY].success is True
        assert results[self.SOURCE_KEY].record_count == 1

    def test_function_app_reads_matching_key(self):
        """The weekly handler must read the same key and store it as ot_advisories."""
        import pathlib

        repo_root = pathlib.Path(__file__).resolve().parent.parent
        source = (repo_root / "function_app.py").read_text(encoding="utf-8")
        assert f'data_by_source.get("{self.SOURCE_KEY}"' in source
        assert 'analysis["ot_advisories"]' in source

    def test_report_renders_ot_advisories_key(self):
        """The report consumes the same analysis key the handler writes."""
        import pathlib

        repo_root = pathlib.Path(__file__).resolve().parent.parent
        source = (repo_root / "src" / "reports" / "weekly_report.py").read_text(encoding="utf-8")
        assert 'analysis_result.get("ot_advisories"' in source

    @pytest.mark.asyncio
    async def test_host_from_secret_overrides_config_default(self):
        """A rapidapi_ics_host credential (from Key Vault) is used over the config default."""
        from src.collectors import ics_advisory_collector as mod
        from src.collectors.ics_advisory_collector import ICSAdvisoryCollector

        seen = {}

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url, headers=None, params=None):
                seen["url"] = url
                seen["host_header"] = headers["x-rapidapi-host"]
                return []

        collector = ICSAdvisoryCollector(
            {"rapidapi_ics_key": "k", "rapidapi_ics_host": "custom-host.example.com"}
        )
        with patch.object(mod, "HTTPClient", lambda *a, **k: _FakeClient()):
            await collector.collect()

        assert seen["host_header"] == "custom-host.example.com"
        assert seen["url"].startswith("https://custom-host.example.com/")


class TestClarotyCollector:
    """Tests for the Claroty xDome collector and OT asset-matching."""

    @pytest.fixture
    def claroty_credentials(self):
        return {"claroty_token": "test-claroty-token"}

    def test_source_name(self, claroty_credentials):
        from src.collectors.claroty_collector import ClarotyCollector

        assert ClarotyCollector(claroty_credentials).source_name == "Claroty"

    def test_enabled_requires_token(self):
        from src.collectors.claroty_collector import ClarotyCollector

        assert ClarotyCollector({"claroty_token": "t"}).enabled is True
        assert ClarotyCollector({}).enabled is False

    def test_registered(self):
        assert "claroty" in list_available_collectors()
        assert get_collector("claroty", {"claroty_token": "t"}).source_name == "Claroty"

    def test_parse_vuln_list_and_string_cves(self, claroty_credentials):
        from src.collectors.claroty_collector import ClarotyCollector

        c = ClarotyCollector(claroty_credentials)
        v = c._parse_vuln({"cve_ids": ["CVE-2026-1", "not-a-cve"], "affected_devices_count": 3,
                           "affected_ot_devices_count": 2})
        assert v["cve_ids"] == ["CVE-2026-1"]
        assert v["affected_devices_count"] == 3 and v["affected_ot_devices_count"] == 2
        # string form is split; a row with no real CVE is dropped
        assert c._parse_vuln({"cve_ids": "CVE-2026-9, CVE-2026-8"})["cve_ids"] == ["CVE-2026-9", "CVE-2026-8"]
        assert c._parse_vuln({"cve_ids": []}) is None

    def test_parse_vuln_reads_exploitation_signals(self, claroty_credentials):
        from src.collectors.claroty_collector import ClarotyCollector

        c = ClarotyCollector(claroty_credentials)
        v = c._parse_vuln({"cve_ids": ["CVE-2026-1"], "is_known_exploited": True,
                           "exploits_count": 3, "epss_score": "0.87"})
        assert v["is_known_exploited"] is True
        assert v["exploits_count"] == 3
        assert v["epss"] == 0.87
        # Missing / unparseable signals degrade to safe defaults.
        m = c._parse_vuln({"cve_ids": ["CVE-2026-2"], "epss_score": "n/a"})
        assert m["exploits_count"] == 0 and m["epss"] is None

    @pytest.mark.asyncio
    async def test_collect_is_noop(self, claroty_credentials):
        """The parallel collector does no bulk pull; matching is a targeted enrichment."""
        from src.collectors.claroty_collector import ClarotyCollector

        result = await ClarotyCollector(claroty_credentials).collect()
        assert result.success is True and result.record_count == 0

    @pytest.mark.asyncio
    async def test_fetch_and_annotate_queries_only_advisory_cves_and_vendors(self, claroty_credentials):
        """Targeted queries: filter vulns by the advisory CVEs and devices by their vendors."""
        from src.collectors import claroty_collector as mod
        from src.collectors.claroty_collector import fetch_and_annotate

        ot = [
            {"advisory_id": "A-1", "vendor": "Gardyn", "cves": ["CVE-2026-13768"]},
            {"advisory_id": "A-2", "vendor": "Mitsubishi Electric", "cves": ["CVE-2099-0"]},
        ]
        seen = {}

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, url, headers=None, json_data=None, data=None, params=None, expected_status=(200,)):
                seen["auth"] = headers["Authorization"]
                if url.endswith("/vulnerabilities/"):
                    seen["cve_filter"] = json_data["filter_by"]
                    return {"vulnerabilities": [
                        {"cve_ids": ["CVE-2026-13768"], "affected_devices_count": 7, "affected_ot_devices_count": 5},
                    ]}
                seen["vendor_filter"] = json_data["filter_by"]
                return {"devices": [{"manufacturer": "Gardyn", "model_family": "", "site_name": "Plant A"}]}

        with patch.object(mod, "HTTPClient", lambda *a, **k: _FakeClient()):
            out = await fetch_and_annotate(ot, claroty_credentials)

        assert seen["auth"] == "Bearer test-claroty-token"
        # Vulnerabilities filtered to affected>0 AND cve_ids in the advisory CVE set.
        assert {"field": "cve_ids", "operation": "in", "value": ["CVE-2026-13768", "CVE-2099-0"]} in \
            seen["cve_filter"]["operands"]
        # Devices filtered to the advisory vendors only (no full-inventory pull).
        assert seen["vendor_filter"] == {"field": "manufacturer", "operation": "in",
                                         "value": ["Gardyn", "Mitsubishi Electric"]}
        g = next(a for a in out if a["advisory_id"] == "A-1")
        assert g["affected_assets"] == 7 and g["in_environment"] is True
        assert g["claroty_status"] == "ok"

    @pytest.mark.asyncio
    async def test_fetch_and_annotate_without_token_is_safe(self):
        """No token -> advisories are annotated with zero exposure, no API calls."""
        from src.collectors.claroty_collector import fetch_and_annotate

        out = await fetch_and_annotate([{"advisory_id": "A-1", "vendor": "Gardyn", "cves": ["CVE-1"]}], {})
        assert out[0]["in_environment"] is False and out[0]["affected_assets"] == 0
        assert out[0]["claroty_status"] == "disabled"

    @pytest.mark.asyncio
    async def test_fetch_and_annotate_failure_marks_error_status(self):
        """A failed Claroty query is surfaced as status 'error', not silent zero."""
        from src.collectors import claroty_collector as mod
        from src.collectors.claroty_collector import fetch_and_annotate

        class _FailingClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                raise TimeoutError()

        ot = [{"advisory_id": "A-1", "vendor": "Gardyn", "cves": ["CVE-1"]}]
        with patch.object(mod, "HTTPClient", lambda *a, **k: _FailingClient()):
            out = await fetch_and_annotate(ot, {"claroty_token": "t"})

        assert out[0]["claroty_status"] == "error"
        assert out[0]["affected_assets"] == 0  # unknown, not confirmed-zero

    def test_parse_vuln_reads_cvss(self, claroty_credentials):
        """CVSS score is normalized to a float; a missing/garbage score becomes None."""
        from src.collectors.claroty_collector import ClarotyCollector

        c = ClarotyCollector(claroty_credentials)
        assert c._parse_vuln({"cve_ids": ["CVE-2026-1"], "cvss_v3_score": "9.8"})["cvss"] == 9.8
        assert c._parse_vuln({"cve_ids": ["CVE-2026-1"], "cvss_v3_score": None})["cvss"] is None
        assert c._parse_vuln({"cve_ids": ["CVE-2026-1"], "cvss_v3_score": "n/a"})["cvss"] is None

    @pytest.mark.asyncio
    async def test_fetch_environment_exposure_filters_high_critical_by_cvss(self, claroty_credentials):
        """Env-exposure query filters to OT devices>0 AND High/Critical CVSS, sorts by CVSS desc."""
        from src.collectors import claroty_collector as mod
        from src.collectors.claroty_collector import fetch_environment_exposure

        seen = {}

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, url, headers=None, json_data=None, data=None, params=None, expected_status=(200,)):
                seen["url"] = url
                seen["body"] = json_data
                return {"vulnerabilities": [
                    {"name": "RCE", "cve_ids": ["CVE-2026-18019"], "cvss_v3_score": 9.8,
                     "affected_devices_count": 4088, "affected_ot_devices_count": 3000,
                     "is_known_exploited": True},
                    {"name": "noise", "cve_ids": [], "affected_devices_count": 1},
                ]}

        with patch.object(mod, "HTTPClient", lambda *a, **k: _FakeClient()):
            out = await fetch_environment_exposure(claroty_credentials, limit=5)

        assert seen["url"].endswith("/vulnerabilities/")
        # Compound filter: affects an OT device AND scores High/Critical.
        operands = seen["body"]["filter_by"]["operands"]
        assert seen["body"]["filter_by"]["operation"] == "and"
        assert {"field": "affected_ot_devices_count", "operation": "greater", "value": 0} in operands
        assert {"field": "cvss_v3_score", "operation": "greater_or_equal", "value": 7.0} in operands
        # Ranked by CVSS descending.
        assert seen["body"]["sort_by"] == [{"field": "cvss_v3_score", "order": "desc"}]
        assert seen["body"]["limit"] == 5
        # Row without a usable CVE is dropped; the real one is parsed with cvss + KEV.
        assert len(out) == 1
        assert out[0]["cve_ids"] == ["CVE-2026-18019"] and out[0]["cvss"] == 9.8
        assert out[0]["affected_devices_count"] == 4088 and out[0]["is_known_exploited"] is True

    @pytest.mark.asyncio
    async def test_fetch_environment_exposure_without_token_returns_empty(self):
        """No token -> no API call, empty result (best-effort)."""
        from src.collectors.claroty_collector import fetch_environment_exposure

        assert await fetch_environment_exposure({}) == []

    @pytest.mark.asyncio
    async def test_fetch_environment_exposure_failure_returns_empty(self, claroty_credentials):
        """A failed query degrades to an empty list rather than raising."""
        from src.collectors import claroty_collector as mod
        from src.collectors.claroty_collector import fetch_environment_exposure

        class _FailingClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                raise TimeoutError()

        with patch.object(mod, "HTTPClient", lambda *a, **k: _FailingClient()):
            assert await fetch_environment_exposure(claroty_credentials) == []

    def test_product_match_folds_into_env_assets(self):
        """An advisory with no CVE match still counts if you own the vendor's gear."""
        from src.collectors.claroty_collector import annotate_ot_advisories_with_assets

        advisories = [
            {"advisory_id": "A-1", "vendor": "Gardyn", "product": "Gardyn IoT Hub", "cves": ["CVE-2026-99"]},
        ]
        claroty = [
            {"record_type": "device", "manufacturer": "Gardyn", "model": "IoT Hub", "model_family": ""},
            {"record_type": "device", "manufacturer": "Gardyn", "model": "IoT Hub", "model_family": ""},
            {"record_type": "device", "manufacturer": "Siemens", "model": "S7", "model_family": ""},
        ]
        out = annotate_ot_advisories_with_assets(advisories, claroty)
        assert out[0]["affected_assets"] == 2  # two Gardyn devices
        assert out[0]["in_environment"] is True
        assert out[0]["match_type"] == "product"

    def test_cve_match_beats_product_match_count(self):
        """When both signals fire, the larger asset count is used (max, not sum)."""
        from src.collectors.claroty_collector import annotate_ot_advisories_with_assets

        advisories = [{"advisory_id": "A-1", "vendor": "Gardyn", "cves": ["CVE-2026-13768"]}]
        claroty = [
            {"record_type": "vulnerability", "cve_ids": ["CVE-2026-13768"],
             "affected_devices_count": 5, "affected_ot_devices_count": 4},
            {"record_type": "device", "manufacturer": "Gardyn", "model": "Hub", "model_family": ""},
        ]
        out = annotate_ot_advisories_with_assets(advisories, claroty)
        assert out[0]["affected_assets"] == 5  # max(cve=5, product=1)
        assert out[0]["match_type"] == "cve+product"

    def test_product_match_reports_site_breakdown(self):
        """Matched vendor devices are grouped by site into advisory['sites']."""
        from src.collectors.claroty_collector import annotate_ot_advisories_with_assets

        advisories = [{"advisory_id": "A-1", "vendor": "Gardyn", "cves": []}]
        claroty = [
            {"record_type": "device", "manufacturer": "Gardyn", "model_family": "", "site_name": "Plant A"},
            {"record_type": "device", "manufacturer": "Gardyn", "model_family": "", "site_name": "Plant A"},
            {"record_type": "device", "manufacturer": "Gardyn", "model_family": "", "site_name": "Lab B"},
        ]
        out = annotate_ot_advisories_with_assets(advisories, claroty)
        assert out[0]["affected_assets"] == 3
        assert dict(out[0]["sites"]) == {"Plant A": 2, "Lab B": 1}

    def test_generic_token_alone_does_not_match(self):
        """'Mitsubishi Electric' must not match 'General Electric' on 'electric' alone."""
        from src.collectors.claroty_collector import annotate_ot_advisories_with_assets

        advisories = [{"advisory_id": "A-1", "vendor": "Mitsubishi Electric", "cves": []}]
        claroty = [{"record_type": "device", "manufacturer": "General Electric", "model_family": "",
                    "site_name": "Plant A"}]
        out = annotate_ot_advisories_with_assets(advisories, claroty)
        assert out[0]["in_environment"] is False

    def test_product_match_ignores_short_and_corp_tokens(self):
        """Corp suffixes and short tokens don't create spurious matches."""
        from src.collectors.claroty_collector import annotate_ot_advisories_with_assets

        advisories = [{"advisory_id": "A-1", "vendor": "Acme Inc", "product": "", "cves": []}]
        # A different vendor that only shares the stripped 'inc' / short tokens.
        claroty = [{"record_type": "device", "manufacturer": "Globex Inc", "model": "X", "model_family": ""}]
        out = annotate_ot_advisories_with_assets(advisories, claroty)
        assert out[0]["in_environment"] is False

    def test_annotate_matches_cves_to_assets_and_orders(self):
        from src.collectors.claroty_collector import annotate_ot_advisories_with_assets

        advisories = [
            {"advisory_id": "A-1", "cves": ["CVE-2026-99"]},                 # no match
            {"advisory_id": "A-2", "cves": ["CVE-2026-13768", "CVE-2026-1"]},  # match
        ]
        claroty = [
            {"cve_ids": ["CVE-2026-13768"], "affected_devices_count": 5, "affected_ot_devices_count": 4},
        ]
        out = annotate_ot_advisories_with_assets(advisories, claroty)
        # matched advisory is moved to the front and annotated
        assert out[0]["advisory_id"] == "A-2"
        assert out[0]["affected_assets"] == 5 and out[0]["affected_ot_assets"] == 4
        assert out[0]["in_environment"] is True
        assert out[1]["in_environment"] is False and out[1]["affected_assets"] == 0

    def test_annotate_no_claroty_data_is_safe(self):
        from src.collectors.claroty_collector import annotate_ot_advisories_with_assets

        advisories = [{"advisory_id": "A-1", "cves": ["CVE-2026-1"]}]
        out = annotate_ot_advisories_with_assets(advisories, [])
        assert out[0]["in_environment"] is False and out[0]["affected_assets"] == 0


class TestKevEnrichment:
    """Tests for the CISA KEV ransomware-flag enrichment of the OT tables."""

    @pytest.fixture(autouse=True)
    def _reset_kev_cache(self):
        """The catalog is memoized per run; clear it around each test for isolation."""
        from src.enrichment import kev as mod

        mod.reset_kev_cache()
        yield
        mod.reset_kev_cache()

    _FEED = {
        "vulnerabilities": [
            {"cveID": "CVE-2026-18019", "knownRansomwareCampaignUse": "Known",
             "dueDate": "2026-09-01", "dateAdded": "2026-08-01",
             "vendorProject": "Acme", "product": "PLC", "vulnerabilityName": "RCE in PLC"},
            {"cveID": "CVE-2026-18015", "knownRansomwareCampaignUse": "Unknown",
             "dueDate": "2026-09-15", "dateAdded": "2026-08-02",
             "vendorProject": "Acme", "product": "HMI", "vulnerabilityName": "Info leak"},
        ]
    }

    class _FakeClient:
        def __init__(self, payload):
            self._payload = payload

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None, params=None, auth=None, expected_status=(200,)):
            return self._payload

    @pytest.mark.asyncio
    async def test_fetch_kev_map_parses_ransomware_flag(self):
        from src.enrichment import kev as mod

        with patch.object(mod, "HTTPClient", lambda *a, **k: self._FakeClient(self._FEED)):
            m = await mod.fetch_kev_map()

        assert m["CVE-2026-18019"]["ransomware"] is True
        assert m["CVE-2026-18015"]["ransomware"] is False
        assert m["CVE-2026-18019"]["due_date"] == "2026-09-01"
        # Unified schema also carries the fields the IT Exploited section needs, so the
        # catalog is fetched once and both consumers read this one map.
        assert m["CVE-2026-18019"]["vendor"] == "Acme"
        assert m["CVE-2026-18019"]["product"] == "PLC"
        assert m["CVE-2026-18019"]["name"] == "RCE in PLC"
        assert m["CVE-2026-18019"]["date_added"] == "2026-08-01"

    @pytest.mark.asyncio
    async def test_fetch_kev_map_disabled_returns_empty(self, monkeypatch):
        from types import SimpleNamespace

        from src.enrichment import kev as mod

        monkeypatch.setattr(mod, "collector_config", SimpleNamespace(kev_enrich_enabled=False))
        assert await mod.fetch_kev_map() == {}

    @pytest.mark.asyncio
    async def test_fetch_kev_map_failure_returns_empty(self):
        from src.enrichment import kev as mod

        class _Failing(self._FakeClient):
            async def get(self, *a, **k):
                raise TimeoutError()

        with patch.object(mod, "HTTPClient", lambda *a, **k: _Failing(None)):
            assert await mod.fetch_kev_map() == {}

    @pytest.mark.asyncio
    async def test_fetch_kev_map_memoized_across_calls(self):
        """The catalog downloads once per run; later calls reuse the memoized map."""
        from src.enrichment import kev as mod

        calls = {"n": 0}

        class _Counting(self._FakeClient):
            async def get(self, *a, **k):
                calls["n"] += 1
                return self._payload

        with patch.object(mod, "HTTPClient", lambda *a, **k: _Counting(self._FEED)):
            first = await mod.fetch_kev_map()
            second = await mod.fetch_kev_map()
            forced = await mod.fetch_kev_map(force_refresh=True)

        assert calls["n"] == 2  # one initial fetch + one forced refresh (the middle call is cached)
        assert first is second  # same memoized object
        assert forced["CVE-2026-18019"]["ransomware"] is True

    @pytest.mark.asyncio
    async def test_cve_enricher_uses_shared_map_and_string_ransomware(self):
        """CVEEnricher reads the shared map and keeps the string ransomware contract."""
        from types import SimpleNamespace

        from src.enrichment import kev as kev_mod
        from src.enrichment.cve_enricher import CVEEnricher

        enricher = CVEEnricher()
        # Frozen config; swap the reference to keep web search off in the test.
        enricher.config = SimpleNamespace(enable_web_search=False, max_web_searches_per_run=0)
        with patch.object(kev_mod, "HTTPClient", lambda *a, **k: self._FakeClient(self._FEED)):
            out = await enricher.enrich_cves([
                {"cve_id": "CVE-2026-18019", "description": ""},   # ransomware KEV
                {"cve_id": "CVE-2026-18015", "description": ""},   # KEV, not ransomware
                {"cve_id": "CVE-2099-0", "description": ""},       # not in KEV
            ])

        by_id = {c["cve_id"]: c for c in out}
        # Ransomware KEV entry: string form preserved for the report's exploited-detection.
        assert by_id["CVE-2026-18019"]["in_cisa_kev"] is True
        assert by_id["CVE-2026-18019"]["known_ransomware"] == "Known"
        assert by_id["CVE-2026-18019"]["exploited_by"] == "Ransomware groups"
        assert by_id["CVE-2026-18019"]["affected_product"] == "Acme PLC"
        # Non-ransomware KEV entry: "Unknown" (not the truthy-bool that would misfire).
        assert by_id["CVE-2026-18015"]["known_ransomware"] == "Unknown"
        # Not in KEV.
        assert by_id["CVE-2099-0"]["in_cisa_kev"] is False

    def test_annotate_sets_flags_by_cve_field(self):
        from src.enrichment.kev import annotate_records_with_kev

        kev_map = {
            "CVE-2026-18019": {"ransomware": True, "due_date": "2026-09-15"},
            "CVE-2026-18015": {"ransomware": False, "due_date": "2026-09-01"},
        }
        # Advisory uses "cves"; env-exposure uses "cve_ids". Case-insensitive matching.
        advisories = [
            {"advisory_id": "A-1", "cves": ["cve-2026-18019"]},
            {"advisory_id": "A-2", "cves": ["CVE-2026-18015"]},
            {"advisory_id": "A-3", "cves": ["CVE-2099-0"]},
        ]
        annotate_records_with_kev(advisories, kev_map, "cves")
        assert advisories[0]["known_ransomware"] is True
        assert advisories[0]["in_cisa_kev"] is True
        assert advisories[0]["kev_ransomware_cves"] == ["CVE-2026-18019"]
        assert advisories[0]["kev_due_date"] == "2026-09-15"
        assert advisories[1]["known_ransomware"] is False and advisories[1]["in_cisa_kev"] is True
        assert advisories[2]["known_ransomware"] is False and advisories[2]["in_cisa_kev"] is False
        assert "kev_due_date" not in advisories[2]  # not in KEV -> no deadline

        # Earliest deadline wins when a record spans multiple KEV CVEs.
        vulns = [{"cve_ids": ["CVE-2026-18019", "CVE-2026-18015"]}]
        annotate_records_with_kev(vulns, kev_map, "cve_ids")
        assert vulns[0]["known_ransomware"] is True
        assert vulns[0]["kev_due_date"] == "2026-09-01"

    def test_annotate_empty_map_is_noop(self):
        from src.enrichment.kev import annotate_records_with_kev

        advisories = [{"advisory_id": "A-1", "cves": ["CVE-2026-18019"]}]
        annotate_records_with_kev(advisories, {}, "cves")
        assert "known_ransomware" not in advisories[0]


class TestBreachHibpFlag:
    def test_hibp_off_by_default_on_when_flag_set(self, mock_credentials, monkeypatch):
        from types import SimpleNamespace

        from src.collectors import hibp_breach_collector as mod
        from src.collectors.hibp_breach_collector import HIBPBreachCollector

        # Off by default (not an industry peer source; also mega-breaches dominate).
        assert HIBPBreachCollector(mock_credentials, report_type="quarterly").enabled is False
        # On when the operator opts in (collector_config is a frozen dataclass, so swap the ref).
        monkeypatch.setattr(mod, "collector_config", SimpleNamespace(breach_include_hibp=True))
        assert HIBPBreachCollector(mock_credentials, report_type="quarterly").enabled is True
