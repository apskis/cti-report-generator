"""
OSINT Collector - Curated open source intelligence from vetted RSS feeds.

Reads a user-maintained config file (config/osint_sources.yaml) that lists
trusted public news and intelligence sources. Only sources you explicitly
add and enable will be collected.

No API key required - uses public RSS/Atom feeds.
"""

import asyncio
import logging
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import aiohttp
import feedparser
import yaml

from src.collectors.base import BaseCollector
from src.core.config import enrichment_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "osint_sources.yaml"

# Some feeds (notably CISA / US-CERT, behind a CDN) return HTTP 403 to non-browser
# user agents. Present a realistic browser UA plus feed-appropriate Accept headers so
# those sources are reachable. This only affects the request headers, not parsing.
_REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5",
    "Accept-Language": "en-US,en;q=0.9",
}


def _load_osint_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Load and validate the OSINT sources configuration file."""
    if not path.exists():
        logger.warning(f"OSINT config not found at {path}, no sources will be collected")
        return {
            "sources": [],
            "lookback_days": 7,
            "quarterly_lookback_days": 100,
            "max_articles_per_source": 5,
            "max_total_articles": 30,
        }

    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    return {
        "sources": config.get("sources", []),
        "lookback_days": config.get("lookback_days", 7),
        # Quarterly reports span ~90 days; a 7-day (weekly) lookback silently zeroes out
        # feeds that don't publish daily. Used only when no explicit collection_window is
        # supplied (the CLI quarterly path pins the exact quarter instead).
        "quarterly_lookback_days": config.get("quarterly_lookback_days", 100),
        "max_articles_per_source": config.get("max_articles_per_source", 5),
        "max_total_articles": config.get("max_total_articles", 30),
        # Wayback Machine fallback: for quarterly runs over a historical window, pull
        # archived snapshots of each feed from within the quarter so short-retention feeds
        # (BleepingComputer, US-CERT) recover articles the live feed has since dropped.
        "use_wayback_for_quarterly": config.get("use_wayback_for_quarterly", True),
        "max_wayback_snapshots_per_source": config.get("max_wayback_snapshots_per_source", 6),
    }


def _parse_pub_date(entry: dict) -> datetime | None:
    """Extract publication date from a feed entry."""
    for field in ("published_parsed", "updated_parsed"):
        tp = entry.get(field)
        if tp:
            try:
                from time import mktime

                return datetime.fromtimestamp(mktime(tp), tz=UTC)
            except Exception:
                pass

    for field in ("published", "updated"):
        raw = entry.get(field, "")
        if raw:
            try:
                return parsedate_to_datetime(raw).replace(tzinfo=UTC)
            except Exception:
                pass
    return None


def _clean_html(raw: str) -> str:
    """Strip HTML tags from a string."""
    return re.sub(r"<[^>]+>", "", raw).strip()


class OSINTCollector(BaseCollector):
    """
    Collector for curated open-source intelligence feeds.

    Reads trusted RSS/Atom feeds defined in config/osint_sources.yaml
    and returns recent articles within the lookback window.
    """

    @property
    def source_name(self) -> str:
        return "OSINT"

    @property
    def lookback_days(self) -> int:
        config = _load_osint_config()
        return config.get("lookback_days", 7)

    async def collect(self, report_type: str = "weekly") -> CollectorResult:
        """Fetch articles from all enabled OSINT sources."""
        config = _load_osint_config()
        sources = [s for s in config["sources"] if s.get("enabled", True)]

        if not sources:
            logger.info("No enabled OSINT sources in config")
            return CollectorResult(source=self.source_name, success=True, data=[], record_count=0)

        max_per_source = config["max_articles_per_source"]
        max_total = config["max_total_articles"]
        # A quarterly report covers ~90 days; the weekly 7-day lookback would zero out
        # feeds that don't post daily. When the caller supplies an explicit
        # collection_window (CLI quarterly path) it overrides this via get_date_range.
        lookback = config["quarterly_lookback_days"] if report_type == "quarterly" else config["lookback_days"]

        start_date, end_date = self.get_date_range(days=lookback)
        cutoff = start_date.replace(tzinfo=UTC)
        # Upper bound of the collection window. For a trailing weekly run this is "now"
        # (harmless — nothing is future-dated); for a quarterly run with an explicit
        # collection_window it is the quarter's end, so the per-source article cap fills
        # with IN-quarter articles instead of too-new ones that a later period filter would
        # discard (which previously left every feed reading "0 articles in lookback window").
        window_end = end_date.replace(tzinfo=UTC)

        # Wayback fallback only for a quarterly run over a historical window (an explicit
        # collection_window). Live feeds suffice for a trailing weekly/current window, and
        # augmenting those would just refetch the same recent entries.
        use_archive = (
            report_type == "quarterly"
            and self.collection_window is not None
            and config["use_wayback_for_quarterly"]
        )
        max_snapshots = config["max_wayback_snapshots_per_source"]

        logger.info(
            f"Collecting OSINT from {len(sources)} enabled sources "
            f"(window: {cutoff.date()} to {window_end.date()}"
            f"{'; Wayback archive fallback ON' if use_archive else ''})"
        )

        all_articles: list[dict[str, Any]] = []

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), headers=_REQUEST_HEADERS) as session:
            # If the archive fallback is on, confirm web.archive.org is actually reachable
            # ONCE up front. Corporate web filters commonly block web.archive.org (while
            # leaving archive.org reachable), which would otherwise surface as silent per-feed
            # zeros. Disable the fallback and log a clear, attributed reason instead.
            if use_archive:
                from src.collectors.wayback import wayback_reachable

                ok, reason = await wayback_reachable(session)
                if not ok:
                    logger.warning(
                        "OSINT Wayback fallback disabled: web.archive.org is unreachable on "
                        f"this network ({reason}). Short-retention feeds cannot be backfilled "
                        "from the archive for this quarter; allowlist web.archive.org to enable it."
                    )
                    use_archive = False

            for source in sources:
                if len(all_articles) >= max_total:
                    break

                name = source.get("name", "Unknown")
                url = source.get("url", "")
                category = source.get("category", "OSINT")
                source.get("type", "rss")

                if not url:
                    continue

                try:
                    articles = await self._fetch_rss(
                        session, name, url, category, cutoff, max_per_source, window_end,
                        use_archive=use_archive, max_snapshots=max_snapshots,
                    )
                    all_articles.extend(articles)
                    if articles:
                        logger.info(f"  {name}: {len(articles)} articles")
                    else:
                        logger.debug(f"  {name}: 0 articles in lookback window")

                except Exception as e:
                    logger.warning(f"  {name}: Failed to fetch - {e}")

            all_articles = all_articles[:max_total]

            # Opt-in: fetch each article URL and extract the full body (trafilatura)
            # so the AI sees the whole article, not just the RSS summary snippet.
            if enrichment_config.enable_osint_fulltext:
                await self._enrich_full_text(session, all_articles)

        all_articles.sort(key=lambda a: a.get("published_date", ""), reverse=True)

        logger.info(f"OSINT collection complete: {len(all_articles)} articles from {len(sources)} sources")

        return CollectorResult(source=self.source_name, success=True, data=all_articles, record_count=len(all_articles))

    async def _enrich_full_text(self, session: aiohttp.ClientSession, articles: list[dict[str, Any]]) -> None:
        """Attach extracted article bodies as ``full_text`` (opt-in, best-effort).

        Fetches each article URL and extracts the main content with trafilatura. Any
        failure (missing dependency, HTTP error, unextractable page) is logged and the
        article simply keeps its RSS summary. Bounded concurrency keeps it polite.
        """
        try:
            import trafilatura  # noqa: F401  (import-guarded; optional dependency)
        except ImportError:
            logger.warning(
                "ENABLE_OSINT_FULLTEXT is set but 'trafilatura' is not installed; "
                "skipping full-text extraction (articles keep their RSS summary)."
            )
            return

        max_chars = enrichment_config.osint_fulltext_max_chars
        timeout = aiohttp.ClientTimeout(total=enrichment_config.osint_fulltext_timeout_seconds)
        semaphore = asyncio.Semaphore(8)

        async def _one(article: dict[str, Any]) -> None:
            url = article.get("url")
            if not url:
                return
            async with semaphore:
                text = await self._fetch_full_text(session, url, max_chars, timeout)
            if text:
                article["full_text"] = text

        await asyncio.gather(*(_one(a) for a in articles), return_exceptions=True)
        enriched = sum(1 for a in articles if a.get("full_text"))
        logger.info(f"OSINT full-text extraction: {enriched}/{len(articles)} articles enriched")

    async def _fetch_full_text(
        self,
        session: aiohttp.ClientSession,
        url: str,
        max_chars: int,
        timeout: aiohttp.ClientTimeout,
    ) -> str | None:
        """Fetch a URL and return the extracted main article text (capped), or None."""
        import trafilatura

        try:
            async with session.get(url, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.debug(f"full-text: {url} -> HTTP {resp.status}")
                    return None
                html = await resp.text()
        except Exception as e:
            logger.debug(f"full-text fetch failed for {url}: {e}")
            return None

        try:
            text = trafilatura.extract(html, include_comments=False, include_tables=False)
        except Exception as e:
            logger.debug(f"full-text extract failed for {url}: {e}")
            return None

        if not text:
            return None
        text = text.strip()
        return text[:max_chars] if len(text) > max_chars else text

    async def _fetch_rss(
        self,
        session: aiohttp.ClientSession,
        source_name: str,
        url: str,
        category: str,
        cutoff: datetime,
        max_articles: int,
        window_end: datetime | None = None,
        use_archive: bool = False,
        max_snapshots: int = 6,
    ) -> list[dict[str, Any]]:
        """Fetch a feed and return its freshest articles within [cutoff, window_end].

        When ``use_archive`` is set (quarterly historical run), the live feed is augmented
        with Wayback Machine snapshots of the same URL captured inside the window, so
        short-retention feeds still surface their in-quarter articles. Entries from all
        bodies are deduped by URL (then title), filtered to the window, sorted newest-first,
        and capped at ``max_articles``.
        """
        bodies: list[str] = []

        # Live feed.
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    bodies.append(await resp.text())
                else:
                    logger.warning(f"{source_name}: HTTP {resp.status}")
        except Exception as e:
            logger.warning(f"{source_name}: live fetch failed - {e}")

        # Wayback snapshots from within the window (best-effort, non-fatal). Everything
        # collected so far is from the live feed; anything after is archive-sourced.
        n_live_bodies = len(bodies)
        if use_archive and window_end is not None:
            from src.collectors.wayback import fetch_archived_feed_bodies

            try:
                archived = await fetch_archived_feed_bodies(
                    session, url, cutoff, window_end,
                    max_snapshots=max_snapshots, headers=_REQUEST_HEADERS,
                )
                if archived:
                    logger.info(f"  {source_name}: fetched {len(archived)} Wayback snapshot(s) for the window")
                bodies.extend(archived)
            except Exception as e:
                logger.info(f"  {source_name}: Wayback augmentation failed (non-fatal) - {e}")

        if not bodies:
            return []

        articles: list[dict[str, Any]] = []
        seen: set[str] = set()
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        live_count = 0

        for body_idx, body in enumerate(bodies):
            is_live = body_idx < n_live_bodies
            feed = feedparser.parse(body)
            if feed.bozo and not feed.entries:
                logger.debug(f"{source_name}: feed body parse error - {feed.bozo_exception}")
                continue
            for entry in feed.entries:
                pub_date = _parse_pub_date(entry)
                if pub_date and (pub_date < cutoff or (window_end is not None and pub_date > window_end)):
                    continue

                title = entry.get("title", "").strip()
                link = entry.get("link", "")
                key = (link or title).strip().lower()
                if not key or key in seen:
                    continue
                seen.add(key)
                if is_live:
                    live_count += 1

                summary = _clean_html(entry.get("summary", entry.get("description", "")))
                if len(summary) > 300:
                    summary = summary[:297] + "..."
                cves_found = list(set(re.findall(cve_pattern, f"{title} {summary}")))

                articles.append(
                    {
                        "title": title,
                        "url": link,
                        "summary": summary,
                        "published_date": pub_date.isoformat() if pub_date else "",
                        "source": source_name,
                        "category": category,
                        "cves_mentioned": cves_found,
                        "type": "osint_article",
                    }
                )

        # Freshest first, then cap per source (archived snapshots can add older in-window
        # articles, so a global sort beats live-feed order).
        articles.sort(key=lambda a: a["published_date"] or "", reverse=True)
        if use_archive and len(bodies) > n_live_bodies:
            archive_count = len(articles) - live_count
            logger.info(
                f"  {source_name}: {len(articles)} in-window article(s) "
                f"({live_count} live + {archive_count} recovered from Wayback)"
            )
        return articles[:max_articles]
