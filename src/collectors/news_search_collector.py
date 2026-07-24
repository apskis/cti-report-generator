"""
News-search collector backed by the GDELT DOC 2.0 API.

Unlike the RSS-based OSINT collector (which only serves the newest handful of
entries a feed currently publishes), GDELT is a searchable archive that accepts an
explicit ``startdatetime``/``enddatetime`` window. That makes it the right source for
*historical* backfill — e.g. reconstructing a prior quarter's open-source picture when
the RSS feeds have long since rolled those articles off.

The API is public and requires no key. This collector is NOT in the default enabled
set (normal runs use the curated RSS feeds); it is invoked explicitly during
prior-quarter baseline backfill, or when a user adds ``news_search`` to
``ENABLED_COLLECTORS``.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any

import aiohttp

from src.collectors.base import BaseCollector
from src.core.config import collector_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)

GDELT_DOC_URL = "https://api.gdeltproject.org/api/v2/doc/doc"

_REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
}

_CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"


def _format_gdelt_datetime(dt: datetime) -> str:
    """GDELT wants ``YYYYMMDDHHMMSS`` (UTC)."""
    return dt.strftime("%Y%m%d%H%M%S")


def build_gdelt_params(query: str, start: datetime, end: datetime, max_records: int) -> dict[str, str]:
    """Build the GDELT DOC 2.0 ArtList query parameters for a date-bounded search."""
    return {
        "query": query,
        "mode": "ArtList",
        "format": "json",
        "maxrecords": str(max_records),
        "sort": "DateDesc",
        "startdatetime": _format_gdelt_datetime(start),
        "enddatetime": _format_gdelt_datetime(end),
    }


def _parse_seendate(value: str) -> datetime | None:
    """Parse GDELT's ``seendate`` (e.g. ``20260115T120000Z``) into a UTC datetime."""
    if not value:
        return None
    raw = value.strip().replace("Z", "")
    for fmt in ("%Y%m%dT%H%M%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def parse_gdelt_response(payload: dict[str, Any], category: str = "News Search") -> list[dict[str, Any]]:
    """Normalize a GDELT ArtList JSON payload into OSINT-shaped article dicts.

    The output schema matches the RSS OSINT collector so downstream analysis treats both
    identically: ``title, url, summary, published_date, source, category, cves_mentioned, type``.
    """
    articles: list[dict[str, Any]] = []
    for art in (payload or {}).get("articles", []) or []:
        if not isinstance(art, dict):
            continue
        title = (art.get("title") or "").strip()
        url = art.get("url") or ""
        if not title or not url:
            continue
        pub = _parse_seendate(art.get("seendate", ""))
        domain = art.get("domain") or art.get("sourcecountry") or "GDELT"
        cves = list(set(re.findall(_CVE_PATTERN, title)))
        articles.append(
            {
                "title": title,
                "url": url,
                "summary": "",  # GDELT ArtList has no article body/snippet
                "published_date": pub.isoformat() if pub else "",
                "source": domain,
                "category": category,
                "cves_mentioned": cves,
                "type": "osint_article",
            }
        )
    return articles


class NewsSearchCollector(BaseCollector):
    """Date-bounded open-source news search via the GDELT DOC 2.0 API."""

    @property
    def source_name(self) -> str:
        # Emit under the OSINT bucket so existing OSINT-aware gates/analysis pick it up.
        return "OSINT"

    @property
    def enabled(self) -> bool:
        # Always instantiable; it only actually runs when explicitly selected
        # (backfill, or ENABLED_COLLECTORS), keeping it off normal RSS runs.
        return True

    @property
    def lookback_days(self) -> int:
        return 90

    async def collect(self, report_type: str = "quarterly") -> CollectorResult:
        """Search GDELT for biotech/cyber news within the collection window."""
        start_date, end_date = self.get_date_range()
        # GDELT expects UTC and naive-or-aware both format fine via strftime.
        query = collector_config.news_search_query
        max_records = collector_config.news_search_max_records
        params = build_gdelt_params(query, start_date, end_date, max_records)

        logger.info(
            f"NewsSearch (GDELT): querying {start_date.date()} .. {end_date.date()} "
            f"(max {max_records} records)"
        )

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30), headers=_REQUEST_HEADERS
            ) as session:
                async with session.get(GDELT_DOC_URL, params=params) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.warning(f"NewsSearch (GDELT): HTTP {resp.status} - {body[:200]}")
                        return CollectorResult(source=self.source_name, success=True, data=[], record_count=0)
                    # GDELT returns JSON with a text/... content-type; parse manually.
                    text = await resp.text()

            payload = self._loads(text)
            articles = parse_gdelt_response(payload)
            logger.info(f"NewsSearch (GDELT): {len(articles)} articles")
            return CollectorResult(
                source=self.source_name, success=True, data=articles, record_count=len(articles)
            )
        except Exception as e:
            logger.warning(f"NewsSearch (GDELT) failed (non-critical): {e}")
            return CollectorResult(source=self.source_name, success=False, data=[], error=str(e), record_count=0)

    @staticmethod
    def _loads(text: str) -> dict[str, Any]:
        """Tolerant JSON load — GDELT occasionally returns an empty body for no matches."""
        import json

        text = (text or "").strip()
        if not text:
            return {"articles": []}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.warning("NewsSearch (GDELT): response was not valid JSON; treating as empty")
            return {"articles": []}
