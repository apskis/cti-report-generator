"""
OSINT Collector - Curated open source intelligence from vetted RSS feeds.

Reads a user-maintained config file (config/osint_sources.yaml) that lists
trusted public news and intelligence sources. Only sources you explicitly
add and enable will be collected.

No API key required - uses public RSS/Atom feeds.
"""
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from email.utils import parsedate_to_datetime

import yaml
import feedparser
import aiohttp

from src.collectors.base import BaseCollector
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "osint_sources.yaml"


def _load_osint_config(path: Path = CONFIG_PATH) -> Dict[str, Any]:
    """Load and validate the OSINT sources configuration file."""
    if not path.exists():
        logger.warning(f"OSINT config not found at {path}, no sources will be collected")
        return {"sources": [], "lookback_days": 7, "max_articles_per_source": 5, "max_total_articles": 30}

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    return {
        "sources": config.get("sources", []),
        "lookback_days": config.get("lookback_days", 7),
        "max_articles_per_source": config.get("max_articles_per_source", 5),
        "max_total_articles": config.get("max_total_articles", 30),
    }


def _parse_pub_date(entry: Dict) -> datetime | None:
    """Extract publication date from a feed entry."""
    for field in ("published_parsed", "updated_parsed"):
        tp = entry.get(field)
        if tp:
            try:
                from time import mktime
                return datetime.fromtimestamp(mktime(tp), tz=timezone.utc)
            except Exception:
                pass

    for field in ("published", "updated"):
        raw = entry.get(field, "")
        if raw:
            try:
                return parsedate_to_datetime(raw).replace(tzinfo=timezone.utc)
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
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=[],
                record_count=0
            )

        max_per_source = config["max_articles_per_source"]
        max_total = config["max_total_articles"]
        lookback = config["lookback_days"]

        start_date, _ = self.get_date_range(days=lookback)
        cutoff = start_date.replace(tzinfo=timezone.utc)

        logger.info(f"Collecting OSINT from {len(sources)} enabled sources (lookback: {lookback} days)")

        all_articles: List[Dict[str, Any]] = []

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "CTI-Report-Generator/1.0"}
        ) as session:
            for source in sources:
                if len(all_articles) >= max_total:
                    break

                name = source.get("name", "Unknown")
                url = source.get("url", "")
                category = source.get("category", "OSINT")
                feed_type = source.get("type", "rss")

                if not url:
                    continue

                try:
                    articles = await self._fetch_rss(
                        session, name, url, category, cutoff, max_per_source
                    )
                    all_articles.extend(articles)
                    if articles:
                        logger.info(f"  {name}: {len(articles)} articles")
                    else:
                        logger.debug(f"  {name}: 0 articles in lookback window")

                except Exception as e:
                    logger.warning(f"  {name}: Failed to fetch - {e}")

        all_articles = all_articles[:max_total]
        all_articles.sort(key=lambda a: a.get("published_date", ""), reverse=True)

        logger.info(f"OSINT collection complete: {len(all_articles)} articles from {len(sources)} sources")

        return CollectorResult(
            source=self.source_name,
            success=True,
            data=all_articles,
            record_count=len(all_articles)
        )

    async def _fetch_rss(
        self,
        session: aiohttp.ClientSession,
        source_name: str,
        url: str,
        category: str,
        cutoff: datetime,
        max_articles: int
    ) -> List[Dict[str, Any]]:
        """Fetch and parse an RSS/Atom feed, returning recent articles."""
        async with session.get(url) as resp:
            if resp.status != 200:
                logger.warning(f"{source_name}: HTTP {resp.status}")
                return []
            body = await resp.text()

        feed = feedparser.parse(body)

        if feed.bozo and not feed.entries:
            logger.warning(f"{source_name}: Feed parse error - {feed.bozo_exception}")
            return []

        articles = []
        for entry in feed.entries:
            if len(articles) >= max_articles:
                break

            pub_date = _parse_pub_date(entry)
            if pub_date and pub_date < cutoff:
                continue

            title = entry.get("title", "").strip()
            link = entry.get("link", "")
            summary = _clean_html(entry.get("summary", entry.get("description", "")))
            if len(summary) > 300:
                summary = summary[:297] + "..."

            # Extract CVE mentions from title and summary
            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            cves_found = list(set(re.findall(cve_pattern, f"{title} {summary}")))

            articles.append({
                "title": title,
                "url": link,
                "summary": summary,
                "published_date": pub_date.isoformat() if pub_date else "",
                "source": source_name,
                "category": category,
                "cves_mentioned": cves_found,
                "type": "osint_article",
            })

        return articles
