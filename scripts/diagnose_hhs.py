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

from src.collectors.hhs_fetch import (
    extract_form_action,
    extract_viewstate,
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

    print("HTTP flow can't reach a JS-rendered grid; exploring with a real browser...\n")
    await browser_explore(portal)

    print("\n" + "=" * 70)
    print("End-to-end: running the wired browser export (fetch_hhs_csv_via_browser)...")
    from src.collectors.hhs_breach_collector import parse_hhs_csv
    from src.collectors.hhs_playwright import fetch_hhs_csv_via_browser

    csv_text = await fetch_hhs_csv_via_browser(portal, headless=True)
    if not csv_text:
        print("RESULT: export still did not yield CSV — paste the controls list above.")
        return
    rows = parse_hhs_csv(csv_text)
    print(f"RESULT: CSV captured ({len(csv_text)} bytes), parsed {len(rows)} breach rows.")
    for r in rows[:3]:
        print(f"  - {r['date']}  {r['organization']}  ({r['incident_type']}, records={r['records_exposed']})")


_KW = re.compile(r"csv|excel|export|download|\.xls|spreadsheet", re.I)


def _scan_grid(html: str) -> None:
    """Find export/download controls in the rendered grid HTML (pure Python)."""
    n_tables = len(re.findall(r"<table\b", html, re.I))
    n_iframes = len(re.findall(r"<iframe\b", html, re.I))
    print(f"Tables: {n_tables}   iframes: {n_iframes}")

    found = []
    # Anchors / buttons carry their label as inner text/HTML.
    for m in re.finditer(r"<(a|button)\b([^>]*)>(.*?)</\1>", html, re.I | re.S):
        whole, attrs, inner = m.group(0), m.group(2), m.group(3)
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", inner)).strip()
        if _KW.search(whole):
            found.append((m.group(1).upper(), text[:60], attrs.strip()[:180]))
    # Self-closing controls (inputs/images) carry it in attributes.
    for m in re.finditer(r"<(input|img)\b[^>]*>", html, re.I):
        if _KW.search(m.group(0)):
            found.append((m.group(1).upper(), "", m.group(0)[:180]))

    print(f"Export-ish controls ({len(found)}):")
    for tag, text, attrs in found[:25]:
        print(f"    [{tag}] text={text!r}  {attrs}")

    if not found:
        # Show any element ids/classes containing 'export' as a fallback hint.
        hints = sorted(set(re.findall(r'(?:id|class)="([^"]*(?:export|csv|excel)[^"]*)"', html, re.I)))
        print(f"  (no labelled controls; id/class hints: {hints[:15]})")


async def browser_explore(portal: str) -> None:
    """Drive a real browser to the grid and dump its markup + candidate export controls."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("Playwright not installed: pip install playwright && playwright install chromium")
        return

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context = await browser.new_context(accept_downloads=True)
            page = await context.new_page()
            await page.goto(portal, wait_until="networkidle", timeout=60000)
            print(f"Landing:  url={page.url}  title={await page.title()!r}")

            # Click the "View HIPAA Breach Reports" nav (href="#", JS-driven).
            clicked = False
            for getter in (
                lambda: page.get_by_role("link", name=re.compile("View HIPAA Breach Reports", re.I)),
                lambda: page.get_by_text("View HIPAA Breach Reports", exact=False),
            ):
                try:
                    await getter().first.click(timeout=8000)
                    clicked = True
                    break
                except Exception as e:
                    print(f"  nav click attempt failed: {e}")
            print(f"Clicked 'View HIPAA Breach Reports': {clicked}")
            try:
                await page.wait_for_load_state("networkidle", timeout=30000)
            except Exception:
                pass
            await page.wait_for_timeout(2500)  # let any lazy grid settle
            print(f"After nav: url={page.url}  title={await page.title()!r}")

            html = await page.content()  # post-JS rendered DOM
            grid_path = Path(__file__).resolve().parent.parent / "hhs_grid.html"
            grid_path.write_text(html, encoding="utf-8")
            print(f"Grid page bytes: {len(html)}   (saved -> {grid_path})")
            # Parse the rendered HTML in Python (avoids Playwright's in-browser eval bugs).
            _scan_grid(html)
            print("\nPaste the 'Export-ish controls' list above (attach hhs_grid.html if it's empty).")
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
