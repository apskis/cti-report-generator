"""Diagnose the automated HHS breach-portal CSV export against the LIVE portal.

Run this on a machine with real network access (e.g. Cursor) to see exactly what the
HHS OCR portal returns and whether the automated CSV export works:

    python scripts/diagnose_hhs.py

It prints: portal HTTP status, whether a JSF ViewState + CSV export control were found,
whether the export yielded CSV, and how many breach rows parsed (plus a couple of samples).
No credentials required. If the export fails, the printed diagnostics tell us what to adjust.
"""

from __future__ import annotations

import asyncio

import aiohttp

from src.collectors.hhs_breach_collector import parse_hhs_csv
from src.collectors.hhs_fetch import (
    extract_form_action,
    extract_viewstate,
    fetch_hhs_breach_csv,
    find_export_controls,
    looks_like_hhs_csv,
)
from src.core.config import collector_config

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


async def main() -> None:
    portal = collector_config.hhs_portal_url
    print(f"Portal URL: {portal}\n" + "=" * 70)

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=60), headers=_HEADERS
    ) as session:
        async with session.get(portal) as resp:
            status = resp.status
            html = await resp.text()
    print(f"GET status:            {status}")
    print(f"Page bytes:            {len(html)}")
    print(f"GET already CSV?:      {looks_like_hhs_csv(html)}")
    print(f"ViewState found?:      {bool(extract_viewstate(html))}")
    print(f"Form action:           {extract_form_action(html, portal)}")
    controls = find_export_controls(html)
    print(f"Export controls found: {len(controls)} -> {controls[:8]}")
    print("=" * 70)

    csv_text = await fetch_hhs_breach_csv(portal, _HEADERS)
    if not csv_text:
        print("RESULT: automated export did NOT yield CSV.")
        print("Paste this output back so the fetch flow can be tuned to the live markup,")
        print("or download the CSV from the portal UI and set collector_config.hhs_breach_csv_url")
        print("to that local file path.")
        return

    rows = parse_hhs_csv(csv_text)
    print(f"RESULT: CSV obtained ({len(csv_text)} bytes), parsed {len(rows)} breach rows.")
    for r in rows[:3]:
        print(f"  - {r['date']}  {r['organization']}  ({r['incident_type']}, records={r['records_exposed']})")


if __name__ == "__main__":
    asyncio.run(main())
