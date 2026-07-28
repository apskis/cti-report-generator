"""Internet Archive (Wayback Machine) fallback for short-retention RSS feeds.

Some feeds (notably BleepingComputer and CISA/US-CERT) only expose their most recent
entries — a couple of weeks at most. For a *quarterly* report whose quarter has since
ended, the live feed therefore returns nothing in-window, and the source reads "0 articles".

The Wayback Machine keeps periodic snapshots of those feed URLs. Each snapshot is the feed
*as it looked on that date*, so a snapshot captured inside the reporting quarter contains
that quarter's articles. This module:

    query the CDX index for captures of the feed URL within [start, end]
    -> sample a handful of captures spread across the window
    -> fetch each snapshot's RAW feed body (the ``id_`` form, no Wayback toolbar)

The caller (the OSINT collector) parses those bodies with feedparser and merges the entries
with the live feed, deduped by URL and re-filtered to the window. Everything is best-effort:
any failure logs and yields fewer (or no) archived bodies, never raising.

The pure helpers (URL building, CDX parsing, sampling) are unit-tested offline; the async
orchestrator does the I/O.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from urllib.parse import urlencode

import aiohttp

logger = logging.getLogger(__name__)

_CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
_WEB_ENDPOINT = "https://web.archive.org/web"


def build_cdx_url(feed_url: str, start: datetime, end: datetime) -> str:
    """Build the CDX query URL for successful captures of ``feed_url`` within [start, end].

    ``collapse=timestamp:8`` reduces the result to at most one capture per calendar day, and
    ``filter=statuscode:200`` drops error captures, so the JSON stays small and we sample it
    client-side rather than relying on the server-side ``limit`` (which just takes the first
    N and would bias toward the start of the window).
    """
    params = {
        "url": feed_url,
        "from": start.strftime("%Y%m%d"),
        "to": end.strftime("%Y%m%d"),
        "output": "json",
        "fl": "timestamp,original",
        "filter": "statuscode:200",
        "collapse": "timestamp:8",
    }
    return f"{_CDX_ENDPOINT}?{urlencode(params)}"


def parse_cdx_json(text: str) -> list[tuple[str, str]]:
    """Parse a CDX ``output=json`` response into ``[(timestamp, original_url), ...]``.

    The first row is a header (``["timestamp", "original"]``) and is skipped. Malformed or
    empty responses yield an empty list.
    """
    try:
        rows = json.loads(text or "[]")
    except (ValueError, TypeError):
        return []
    if not isinstance(rows, list) or len(rows) < 2:
        return []
    out: list[tuple[str, str]] = []
    for row in rows[1:]:
        if isinstance(row, list) and len(row) >= 2 and row[0] and row[1]:
            out.append((str(row[0]), str(row[1])))
    return out


def sample_snapshots(rows: list[tuple[str, str]], max_snapshots: int) -> list[tuple[str, str]]:
    """Evenly sample up to ``max_snapshots`` captures spread across the window.

    Captures are chronological, and consecutive daily captures share almost all of their
    entries, so fetching every one is wasteful. Even spacing across the list maximizes the
    distinct articles recovered per request. The first and last captures are always kept.
    """
    if max_snapshots <= 0 or not rows:
        return []
    if len(rows) <= max_snapshots:
        return list(rows)
    if max_snapshots == 1:
        return [rows[len(rows) // 2]]
    step = (len(rows) - 1) / (max_snapshots - 1)
    picked: list[tuple[str, str]] = []
    seen_idx: set[int] = set()
    for i in range(max_snapshots):
        idx = round(i * step)
        if idx not in seen_idx:
            seen_idx.add(idx)
            picked.append(rows[idx])
    return picked


def snapshot_raw_url(timestamp: str, original: str) -> str:
    """URL for a snapshot's RAW original bytes (``id_`` suffix suppresses the Wayback toolbar).

    Without ``id_`` the archive rewrites the response and injects its toolbar, which corrupts
    the XML; ``id_`` returns the feed exactly as captured.
    """
    return f"{_WEB_ENDPOINT}/{timestamp}id_/{original}"


async def wayback_reachable(
    session: aiohttp.ClientSession, *, per_request_timeout: int = 10
) -> tuple[bool, str]:
    """Probe whether web.archive.org's CDX API is reachable, returning (ok, reason).

    A single tiny CDX query. Corporate web filters commonly intercept web.archive.org and
    answer with a synthetic block page (e.g. HTTP 498 + an nginx 404 body) while leaving the
    bare archive.org host reachable — so a non-200, or a 200 whose body is not the expected
    JSON array, is treated as "blocked". Lets the collector disable the archive fallback once
    and log a clear, attributed reason instead of emitting silent zeros per feed.
    """
    probe = f"{_CDX_ENDPOINT}?url=example.com&output=json&limit=1"
    timeout = aiohttp.ClientTimeout(total=per_request_timeout)
    try:
        async with session.get(probe, timeout=timeout) as resp:
            body = (await resp.text()).lstrip()
            if resp.status != 200:
                return False, f"HTTP {resp.status}"
            if not body.startswith("["):
                return False, "non-JSON response (likely a proxy/WAF block page)"
            return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


async def fetch_archived_feed_bodies(
    session: aiohttp.ClientSession,
    feed_url: str,
    start: datetime,
    end: datetime,
    *,
    max_snapshots: int = 6,
    headers: dict | None = None,
    per_request_timeout: int = 20,
) -> list[str]:
    """Return raw feed bodies from Wayback snapshots of ``feed_url`` within [start, end].

    Best-effort and bounded: at most ``max_snapshots`` snapshots, fetched concurrently. Any
    CDX or snapshot failure is logged and skipped; the return is whatever bodies succeeded.
    """
    timeout = aiohttp.ClientTimeout(total=per_request_timeout)
    try:
        async with session.get(build_cdx_url(feed_url, start, end), timeout=timeout) as resp:
            if resp.status != 200:
                logger.info(f"Wayback CDX for {feed_url}: HTTP {resp.status}")
                return []
            rows = parse_cdx_json(await resp.text())
    except Exception as e:
        logger.info(f"Wayback CDX query failed for {feed_url}: {e}")
        return []

    picks = sample_snapshots(rows, max_snapshots)
    if not picks:
        return []

    async def _one(timestamp: str, original: str) -> str | None:
        raw_url = snapshot_raw_url(timestamp, original)
        try:
            async with session.get(raw_url, timeout=timeout, headers=headers) as resp:
                if resp.status != 200:
                    return None
                return await resp.text()
        except Exception as e:
            logger.debug(f"Wayback snapshot fetch failed ({raw_url}): {e}")
            return None

    results = await asyncio.gather(*(_one(ts, orig) for ts, orig in picks), return_exceptions=True)
    return [r for r in results if isinstance(r, str) and r]
