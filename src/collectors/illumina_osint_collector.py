"""
Illumina OSINT Collector for Quarterly Reports.

Fetches current public information about Illumina's products, market position,
regulatory status, and partnerships from official sources.
"""

import logging
import re
import ssl
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import aiohttp
import certifi
from bs4 import BeautifulSoup

from src.collectors.base import BaseCollector, CollectorResult
from src.core.config import customer_profile

logger = logging.getLogger(__name__)

# Browser-style headers: some IR/CDN feeds reject the default aiohttp User-Agent.
_FEED_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, application/json;q=0.8, */*;q=0.5",
    "Accept-Language": "en-US,en;q=0.9",
}


class IlluminaOSINTCollector(BaseCollector):
    """
    Collector for Illumina public information.

    Fetches from:
    0. Durable strategic profile (from customer_profile config; always present)
    1. SEC EDGAR submissions API (material filings only)
    2. Investor-relations press releases (RSS/Atom/JSON feed, HTML scrape fallback)
    3. Web search fallback (not yet implemented)

    Returns a consolidated context string for AI analysis.

    NOTE: This collector only runs for quarterly reports.
    """

    def __init__(self, credentials: dict[str, str] = None, report_type: str = "weekly"):
        super().__init__(credentials or {}, report_type)

    @property
    def source_name(self) -> str:
        """Unique identifier for this data source."""
        return customer_profile.osint_source_name

    @property
    def enabled(self) -> bool:
        """Only enable for quarterly reports."""
        return self.report_type == "quarterly"

    async def collect(self, lookback_days: int = 90, report_type: str = "quarterly", **kwargs) -> CollectorResult:
        """
        Collect Illumina public information for quarterly context.

        Args:
            credentials: API credentials (not needed for public sources)
            lookback_days: Time window (not used - we get latest info)
            **kwargs: Additional parameters

        Returns:
            CollectorResult with illumina_context string
        """
        try:
            logger.info("Starting Illumina OSINT collection for quarterly report")

            context_parts = []

            # SOURCE 0: Durable strategic profile (always present). This is the grounding
            # the geopolitical/breach analysis connects intelligence to, so relevance holds
            # even when the live scrapes below are thin or fail.
            if customer_profile.strategic_profile.strip():
                context_parts.append(
                    f"## {customer_profile.name} Strategic Profile "
                    f"(durable, threat-relevant attributes — use to ground relevance to "
                    f"{customer_profile.name})\n{customer_profile.strategic_profile.strip()}\n"
                )

            # SOURCE 1: SEC EDGAR submissions
            try:
                sec_data = await self._fetch_sec_edgar()
                if sec_data:
                    context_parts.append(f"## SEC Filings (Recent)\n{sec_data}\n")
            except Exception as e:
                logger.warning(f"Failed to fetch SEC EDGAR data: {e}")

            # SOURCE 2: Investor-relations press releases. Prefer a stable RSS/JSON feed;
            # fall back to HTML scraping only if no feed responds (the JS-rendered pages
            # are brittle). Both are labeled the same so downstream treats them uniformly.
            ir_data = ""
            try:
                ir_data = await self._fetch_ir_feed(lookback_days=lookback_days)
            except Exception as e:
                logger.warning(f"Failed to fetch IR press-release feed: {e}")
            if not ir_data:
                try:
                    ir_data = await self._fetch_investor_relations()
                except Exception as e:
                    logger.warning(f"Failed to scrape investor relations HTML: {e}")
            if ir_data:
                context_parts.append(f"## Investor Relations Press Releases\n{ir_data}\n")

            # SOURCE 4: Web search fallback
            # TODO: Add web search utility integration when available
            # For now, log and skip
            logger.info("Web search source not implemented yet - skipping")

            # Combine all context parts
            illumina_context = "\n".join(context_parts)

            # Truncate to ~2000 tokens (roughly 8000 chars)
            if len(illumina_context) > 8000:
                illumina_context = illumina_context[:8000] + "\n\n[truncated for length]"

            logger.info(f"Illumina OSINT collection complete: {len(illumina_context)} chars")

            return CollectorResult(
                success=True,
                source=self.source_name,
                data=[{"illumina_context": illumina_context}],
                record_count=1,
                error=None,
            )

        except Exception as e:
            logger.error(f"Error in Illumina OSINT collection: {e}", exc_info=True)
            return CollectorResult(success=False, source=self.source_name, data=[], record_count=0, error=str(e))

    # SEC forms that carry strategic / material signal. Everything else (insider-trade
    # Form 3/4/5, Form 144, ownership SC 13D/G, etc.) is noise for threat intelligence
    # and must not crowd out the material filings.
    _MATERIAL_SEC_FORMS = (
        "10-K",
        "10-Q",
        "8-K",
        "20-F",
        "6-K",
        "DEF 14A",
        "40-F",
        "S-1",
        "S-3",
    )

    # 8-K item codes worth labeling; Item 1.05 (Material Cybersecurity Incidents) is the
    # single most report-relevant disclosure a public company can make.
    _EIGHTK_ITEMS = {
        "1.01": "Material Definitive Agreement",
        "1.05": "Material Cybersecurity Incident",
        "2.01": "Completion of Acquisition/Disposition",
        "2.02": "Results of Operations",
        "3.01": "Delisting / Listing Standards",
        "4.02": "Non-Reliance on Prior Financials",
        "5.02": "Executive/Director Change",
        "7.01": "Regulation FD Disclosure",
        "8.01": "Other Events",
    }

    _SEC_CIK = "1110803"  # Illumina Inc. Central Index Key

    async def _fetch_sec_edgar(self) -> str:
        """
        Fetch recent MATERIAL SEC filings from EDGAR (10-K/10-Q/8-K/DEF 14A, not
        insider-trade forms), formatted with human descriptions and citeable URLs.

        Returns:
            Formatted string of recent material filing descriptions
        """
        url = f"https://data.sec.gov/submissions/CIK{int(self._SEC_CIK):010d}.json"
        headers = {"User-Agent": f"{customer_profile.name}-CTI-Pipeline {customer_profile.security_contact}"}

        # Create SSL context with certifi certificates
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(ssl=ssl_context)

        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    logger.warning(f"SEC EDGAR API returned status {response.status}")
                    return ""

                data = await response.json()
                return self._format_sec_filings(data, cik=self._SEC_CIK, max_items=6)

    @classmethod
    def _format_sec_filings(cls, data: dict, cik: str, max_items: int = 6) -> str:
        """Pure formatter: pick the most recent MATERIAL filings and render them.

        Filters out insider-trade / ownership noise, prefers a human-readable
        description, annotates 8-K item codes (highlighting cyber incidents), and
        includes a citeable filing-index URL. Kept pure (no network) so it is unit-testable.
        """
        recent = (data or {}).get("filings", {}).get("recent", {})
        forms = recent.get("form", []) or []
        dates = recent.get("filingDate", []) or []
        descriptions = recent.get("primaryDocDescription", []) or []
        accessions = recent.get("accessionNumber", []) or []
        items = recent.get("items", []) or []

        material = {f.upper() for f in cls._MATERIAL_SEC_FORMS}
        lines: list[str] = []
        for i, form in enumerate(forms):
            if len(lines) >= max_items:
                break
            if (form or "").upper() not in material:
                continue

            date = dates[i] if i < len(dates) else "N/A"
            desc = descriptions[i] if i < len(descriptions) else ""
            # For an 8-K, the item codes carry the actual signal ("why did they file?").
            annotation = ""
            if (form or "").upper().startswith("8-K") and i < len(items) and items[i]:
                labeled = []
                for code in [c.strip() for c in str(items[i]).split(",") if c.strip()]:
                    label = cls._EIGHTK_ITEMS.get(code)
                    labeled.append(f"{code} {label}" if label else code)
                if labeled:
                    annotation = f" [Items: {'; '.join(labeled)}]"
            label = desc.strip() or f"{form} filing"

            # Build a citeable filing-index URL from the accession number.
            url = ""
            if i < len(accessions) and accessions[i]:
                acc_nodash = accessions[i].replace("-", "")
                url = f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/{acc_nodash}/"

            entry = f"- {date}: {form} - {label}{annotation}"
            if url:
                entry += f"\n  URL: {url}"
            lines.append(entry)

        if not lines:
            return "No recent material filings (10-K/10-Q/8-K/DEF 14A) found in the lookback window"
        return "\n".join(lines)

    async def _fetch_ir_feed(self, lookback_days: int = 90) -> str:
        """Fetch investor-relations press releases from a stable RSS/Atom/JSON feed.

        Tries each configured ``ir_feed_urls`` in order and returns the first one that
        yields recent items. Feeds are far more reliable than scraping the JS-rendered
        news pages. Returns an empty string if no feed responds (caller falls back to HTML).
        """
        cutoff = datetime.now(UTC) - timedelta(days=lookback_days)
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(ssl=ssl_context)

        async with aiohttp.ClientSession(
            connector=connector, headers=_FEED_HEADERS, timeout=aiohttp.ClientTimeout(total=15)
        ) as session:
            for feed_url in customer_profile.ir_feed_urls:
                try:
                    async with session.get(feed_url) as resp:
                        if resp.status != 200:
                            logger.debug(f"IR feed {feed_url} -> HTTP {resp.status}")
                            continue
                        body = await resp.read()
                except Exception as e:
                    logger.debug(f"IR feed {feed_url} error: {e}")
                    continue

                formatted = self._format_feed_entries(body, cutoff, max_items=8)
                if formatted:
                    logger.info(f"IR feed: using {feed_url}")
                    return formatted
                logger.debug(f"IR feed {feed_url} parsed but yielded no recent items")

        return ""

    @classmethod
    def _format_feed_entries(cls, body, cutoff: datetime, max_items: int = 8) -> str:
        """Pure formatter for a feed body (RSS/Atom via feedparser, or JSON).

        Keeps only items on/after ``cutoff`` (undated items are kept). Pure/no-network
        so the parsing is unit-testable; the JSON path uses only the standard library.
        """
        text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
        stripped = text.lstrip()
        if stripped[:1] in ("{", "["):
            json_out = cls._format_json_feed(stripped, cutoff, max_items)
            if json_out:
                return json_out
            # fall through to feedparser in case it was XML with odd leading chars

        import feedparser

        feed = feedparser.parse(text)
        items: list[str] = []
        for entry in getattr(feed, "entries", []) or []:
            title = cls._clean_text(entry.get("title", ""))
            link = entry.get("link", "")
            if not title or not link:
                continue
            pub = cls._entry_date(entry)
            if pub and pub < cutoff:
                continue
            items.append(cls._format_feed_line(title, link, pub))
            if len(items) >= max_items:
                break
        return "\n".join(items)

    @classmethod
    def _format_json_feed(cls, text: str, cutoff: datetime, max_items: int = 8) -> str:
        """Best-effort JSON feed parser (JSONFeed standard + common IR-API shapes)."""
        import json

        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return ""

        # Accept either a top-level list, a JSONFeed {"items": [...]}, or common
        # IR-API wrappers like {"GetPressReleaseListResult": [...]} / {"news": [...]}.
        candidates = None
        if isinstance(data, list):
            candidates = data
        elif isinstance(data, dict):
            for key in ("items", "news", "results", "data", "GetPressReleaseListResult", "pressReleases"):
                if isinstance(data.get(key), list):
                    candidates = data[key]
                    break
        if not candidates:
            return ""

        items: list[str] = []
        for rec in candidates:
            if not isinstance(rec, dict):
                continue
            title = cls._clean_text(
                str(rec.get("title") or rec.get("headline") or rec.get("Headline") or rec.get("name") or "")
            )
            link = str(rec.get("url") or rec.get("link") or rec.get("LinkToDetailPage") or rec.get("permalink") or "")
            if not title or not link:
                continue
            raw_date = rec.get("date_published") or rec.get("date") or rec.get("PressReleaseDate") or rec.get("pubDate")
            pub = cls._parse_iso_or_rfc(str(raw_date)) if raw_date else None
            if pub and pub < cutoff:
                continue
            items.append(cls._format_feed_line(title, link, pub))
            if len(items) >= max_items:
                break
        return "\n".join(items)

    @staticmethod
    def _format_feed_line(title: str, link: str, pub: datetime | None) -> str:
        prefix = f"{pub.date().isoformat()}: " if pub else ""
        return f"- {prefix}{title}\n  URL: {link}"

    @staticmethod
    def _entry_date(entry: dict) -> datetime | None:
        """Extract a publication date from a feedparser entry."""
        from time import mktime

        for field in ("published_parsed", "updated_parsed"):
            tp = entry.get(field)
            if tp:
                try:
                    return datetime.fromtimestamp(mktime(tp), tz=UTC)
                except Exception:
                    pass
        for field in ("published", "updated"):
            raw = entry.get(field, "")
            if raw:
                dt = IlluminaOSINTCollector._parse_iso_or_rfc(raw)
                if dt:
                    return dt
        return None

    @staticmethod
    def _parse_iso_or_rfc(raw: str) -> datetime | None:
        """Parse an ISO-8601 or RFC-2822 date string to a tz-aware UTC datetime."""
        raw = (raw or "").strip()
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
        try:
            return parsedate_to_datetime(raw).replace(tzinfo=UTC)
        except (TypeError, ValueError):
            return None

    async def _fetch_investor_relations(self) -> str:
        """
        Fetch press releases and validate URLs from Illumina investor relations.

        Returns:
            Formatted string of press release headlines with validated URLs
        """
        # Try the main investor page which should have press releases
        url = "https://investor.illumina.com/investors/default.aspx"

        # Create SSL context with certifi certificates
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(ssl=ssl_context)

        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    logger.warning(f"Illumina IR page returned status {response.status}")
                    return ""

                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")

                # Try to find press release items
                press_releases = []

                # Common patterns for IR pages
                selectors = [
                    ".press-release-item",
                    ".module_pressrelease",
                    "article.press-release",
                    ".pressrelease",
                    ".news-list-item",
                ]

                for selector in selectors:
                    items = soup.select(selector)
                    if items:
                        for item in items[:8]:
                            # Try to extract headline and date
                            headline_elem = item.find(["h3", "h2", "a"])
                            date_elem = item.find(["time", "span", "div"], class_=re.compile(r"date|time"))

                            headline = self._clean_text(headline_elem.get_text()) if headline_elem else "No title"
                            date = self._clean_text(date_elem.get_text()) if date_elem else ""

                            # Extract URL
                            link_elem = item.find("a", href=True)
                            article_url = None
                            if link_elem:
                                href = link_elem["href"]
                                # Handle relative URLs
                                if href.startswith("/"):
                                    article_url = f"https://investor.illumina.com{href}"
                                elif href.startswith("http"):
                                    article_url = href

                            if headline and headline != "No title" and article_url:
                                press_releases.append((headline, date, article_url))
                        break

                if not press_releases:
                    # Fallback: try to find any links that look like press releases
                    links = soup.find_all("a", href=re.compile(r"press-release|news"))
                    for link in links[:8]:
                        text = self._clean_text(link.get_text())
                        href = link.get("href", "")

                        if text and len(text) > 10 and href:  # Skip short navigation links
                            # Handle relative URLs
                            if href.startswith("/"):
                                article_url = f"https://investor.illumina.com{href}"
                            elif href.startswith("http"):
                                article_url = href
                            else:
                                continue

                            press_releases.append((text, "", article_url))

                if not press_releases:
                    logger.warning("Could not parse Illumina IR page - page structure may have changed")
                    return "Unable to parse investor relations page (page structure changed)"

                # Validate URLs and format output
                validated_items = []
                for headline, date, article_url in press_releases[:6]:  # Limit to 6 items
                    # Validate URL is accessible
                    is_valid = await self._validate_url(article_url, session)
                    if is_valid:
                        date_str = f"{date}: " if date else ""
                        validated_items.append(f"- {date_str}{headline}\n  URL: {article_url}")
                    else:
                        logger.warning(f"Skipping broken IR link: {article_url}")

                if not validated_items:
                    return "Investor relations page accessible but all press release links are broken"

                return "\n".join(validated_items)

    async def _validate_url(self, url: str, session: aiohttp.ClientSession) -> bool:
        """
        Validate that a URL is accessible (returns 200 OK).

        Args:
            url: URL to validate
            session: aiohttp session to use

        Returns:
            True if URL is accessible, False otherwise
        """
        try:
            async with session.head(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    return True
                elif response.status == 405:  # HEAD not allowed, try GET
                    async with session.get(
                        url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)
                    ) as get_response:
                        return get_response.status == 200
                else:
                    logger.debug(f"URL validation failed for {url}: status {response.status}")
                    return False
        except Exception as e:
            logger.debug(f"URL validation error for {url}: {e}")
            return False

    @staticmethod
    def _clean_text(text: str) -> str:
        """
        Clean extracted text by removing extra whitespace, HTML artifacts, and navigation text.

        Args:
            text: Raw text to clean

        Returns:
            Cleaned text string
        """
        if not text:
            return ""

        # Remove extra whitespace and normalize
        text = re.sub(r"\s+", " ", text)
        text = text.strip()

        # Remove common navigation/boilerplate phrases
        skip_phrases = [
            "skip to main content",
            "cookie policy",
            "privacy policy",
            "all rights reserved",
            "read more",
            "learn more",
            "click here",
        ]

        text_lower = text.lower()
        for phrase in skip_phrases:
            if phrase in text_lower:
                return ""

        # Remove very short strings (likely not useful content)
        if len(text) < 10:
            return ""

        return text
