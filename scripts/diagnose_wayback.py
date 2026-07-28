"""Diagnose the OSINT Wayback fallback against the LIVE Internet Archive.

Run on a machine with real network access (e.g. Cursor) to see, per enabled feed, how many
in-quarter articles the LIVE feed serves vs. how many the Wayback Machine recovers:

    python scripts/diagnose_wayback.py            # previous calendar quarter
    python scripts/diagnose_wayback.py 2026 2     # explicit year + quarter

For each feed it prints:
  - live in-window article count (what the current collector gets from the live feed alone)
  - Wayback CDX capture count for the quarter, snapshots sampled/fetched
  - archive-recovered in-window article count (unique, beyond the live feed)
  - a few sample recovered titles + dates

If the archive column is populated, the fix works and the coverage-gap findings for those
feeds will clear on the next real quarterly run. If CDX returns 0 captures for a feed, that
feed genuinely isn't archived at that URL (an honest, logged gap).
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, date, datetime, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aiohttp
import feedparser

from src.collectors.osint_collector import _REQUEST_HEADERS, _load_osint_config, _parse_pub_date
from src.collectors.wayback import (
    build_cdx_url,
    fetch_archived_feed_bodies,
    parse_cdx_json,
    sample_snapshots,
)
from src.core.reporting_period import make_period, previous_quarter


def _resolve_quarter(argv: list[str]):
    if len(argv) >= 3:
        return make_period(int(argv[1]), int(argv[2]))
    today = date.today()
    q = (today.month - 1) // 3 + 1
    py, pq = previous_quarter(today.year, q)
    return make_period(py, pq)


def _in_window_articles(bodies: list[str], cutoff: datetime, window_end: datetime) -> list[tuple[str, str]]:
    """Return unique (title, iso_date) for entries within [cutoff, window_end] across bodies."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for body in bodies:
        feed = feedparser.parse(body)
        for entry in feed.entries:
            pub = _parse_pub_date(entry)
            if pub and (pub < cutoff or pub > window_end):
                continue
            title = (entry.get("title") or "").strip()
            link = (entry.get("link") or "").strip()
            key = (link or title).lower()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append((title, pub.date().isoformat() if pub else "?"))
    return out


async def _live_bodies(session, url: str) -> list[str]:
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                print(f"      live GET -> HTTP {resp.status}")
                return []
            return [await resp.text()]
    except Exception as e:
        print(f"      live GET failed: {e}")
        return []


async def main() -> None:
    period = _resolve_quarter(sys.argv)
    cutoff = datetime.combine(period.start, time.min).replace(tzinfo=UTC)
    window_end = datetime.combine(period.end, time.max).replace(tzinfo=UTC)
    print(f"Reporting quarter: {period.label}  ({period.start} to {period.end})")
    print("=" * 78)

    config = _load_osint_config()
    feeds = [s for s in config["sources"] if s.get("enabled", True)]
    max_snapshots = config["max_wayback_snapshots_per_source"]

    summary: list[tuple[str, int, int, int]] = []

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30), headers=_REQUEST_HEADERS
    ) as session:
        for feed in feeds:
            name = feed.get("name", "?")
            url = feed.get("url", "")
            print(f"\n{name}\n  {url}")
            if not url:
                continue

            # 1) Live feed (windowed).
            live = await _live_bodies(session, url)
            live_articles = _in_window_articles(live, cutoff, window_end)
            print(f"  LIVE in-window articles: {len(live_articles)}")

            # 2) Wayback CDX capture count for the quarter.
            n_captures = 0
            try:
                async with session.get(build_cdx_url(url, cutoff, window_end)) as resp:
                    cdx_rows = parse_cdx_json(await resp.text()) if resp.status == 200 else []
                    n_captures = len(cdx_rows)
                    picks = sample_snapshots(cdx_rows, max_snapshots)
                    print(f"  Wayback CDX captures in quarter: {n_captures}   (sampling {len(picks)})")
            except Exception as e:
                print(f"  Wayback CDX query failed: {e}")

            # 3) Archive-recovered articles (unique, beyond live).
            archived = await fetch_archived_feed_bodies(
                session, url, cutoff, window_end, max_snapshots=max_snapshots, headers=_REQUEST_HEADERS
            )
            live_keys = {t.lower() for t, _ in live_articles}
            arch_articles = [a for a in _in_window_articles(archived, cutoff, window_end) if a[0].lower() not in live_keys]
            print(f"  Wayback snapshots fetched: {len(archived)}   ARCHIVE-recovered new in-window articles: {len(arch_articles)}")
            for title, d in arch_articles[:4]:
                print(f"      + [{d}] {title[:80]}")

            summary.append((name, len(live_articles), n_captures, len(arch_articles)))

    print("\n" + "=" * 78)
    print(f"{'Feed':34} {'live':>5} {'captures':>9} {'archive+':>9}")
    print("-" * 78)
    for name, live_n, caps, arch_n in summary:
        print(f"{name[:34]:34} {live_n:>5} {caps:>9} {arch_n:>9}")
    print("-" * 78)
    print("live+archive is what the quarterly collector now sees per feed. A feed with")
    print("live=0 but archive+>0 is a coverage gap the Wayback fallback closes.")


if __name__ == "__main__":
    asyncio.run(main())
