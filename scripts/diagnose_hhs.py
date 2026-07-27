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
import re
import sys
from pathlib import Path

# Allow running this script directly (adds the repo root to sys.path for src imports).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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


def _scan(html: str) -> None:
    """Print structural signals so the correct export flow can be designed from real markup."""
    forms = re.findall(r'<form\b[^>]*\baction\s*=\s*"([^"]*)"', html, re.I)
    print(f"Form actions ({len(forms)}): {forms}")

    links = re.findall(r'<a\b[^>]*\bhref\s*=\s*"([^"]*)"[^>]*>(.*?)</a>', html, re.I | re.S)
    interesting = [
        (href, re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", text)).strip()[:60])
        for href, text in links
        if re.search(r"csv|export|download|report|investigat|breach|archive", href + " " + text, re.I)
    ]
    print(f"Interesting links ({len(interesting)}):")
    for href, text in interesting[:25]:
        print(f"    {text!r:45} -> {href}")

    scripts = re.findall(r'<script\b[^>]*\bsrc\s*=\s*"([^"]*)"', html, re.I)
    print(f"Script srcs ({len(scripts)}): {scripts[:10]}")

    markers = ["csv", "export", "datatable", "lazy", "primefaces", "jsf.js", "widget", "iframe"]
    hits = {m: html.lower().count(m) for m in markers if html.lower().count(m)}
    print(f"Marker counts: {hits}")


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
    print("-" * 70)
    _scan(html)

    out_path = Path(__file__).resolve().parent.parent / "hhs_page.html"
    out_path.write_text(html, encoding="utf-8")
    print(f"\nSaved raw HTML -> {out_path}")
    print("(Paste the above output; attach hhs_page.html if the links don't reveal the data view.)")
    print("=" * 70)

    csv_text = await fetch_hhs_breach_csv(portal, _HEADERS)
    if not csv_text:
        print("HTTP export did not yield CSV (expected — portal is JS-rendered).")
        print("Trying headless-browser export (Playwright)...")
        from src.collectors.hhs_playwright import fetch_hhs_csv_via_browser

        csv_text = await fetch_hhs_csv_via_browser(portal, headless=True)

    if not csv_text:
        print("RESULT: automated export did NOT yield CSV.")
        print("If Playwright is missing: pip install playwright && playwright install chromium")
        print("Otherwise paste this output; or download the CSV from the portal UI and set")
        print("collector_config.hhs_breach_csv_url to that local file path.")
        return

    rows = parse_hhs_csv(csv_text)
    print(f"RESULT: CSV obtained ({len(csv_text)} bytes), parsed {len(rows)} breach rows.")
    for r in rows[:3]:
        print(f"  - {r['date']}  {r['organization']}  ({r['incident_type']}, records={r['records_exposed']})")


if __name__ == "__main__":
    asyncio.run(main())
