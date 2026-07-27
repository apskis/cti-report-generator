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

            html = await page.content()
            print(f"Grid page bytes: {len(html)}   tables: ", end="")
            print(await page.eval_on_selector_all("table", "els => els.length"))

            # Any control that looks like an export/download (CSV/Excel/etc.).
            controls = await page.eval_on_selector_all(
                "a, button, [role=button], span[onclick], img, input",
                r"""els => els.map(e => ({
                    tag: e.tagName,
                    text: (e.innerText||e.value||e.title||e.alt||'').replace(/\s+/g,' ').trim().slice(0,50),
                    id: e.id||'', title: e.title||'',
                    href: (e.getAttribute && e.getAttribute('href'))||'',
                    cls: (e.className||'').toString().slice(0,60)
                })).filter(o => /csv|excel|export|download|\.xls|spreadsheet/i.test(
                    o.text+' '+o.id+' '+o.title+' '+o.href+' '+o.cls))""",
            )
            print(f"Export-ish controls on grid ({len(controls)}):")
            for c in controls[:20]:
                print(f"    {c}")

            grid_path = Path(__file__).resolve().parent.parent / "hhs_grid.html"
            grid_path.write_text(html, encoding="utf-8")
            print(f"\nSaved grid HTML -> {grid_path}")
            print("Paste the 'Export-ish controls' list above (and attach hhs_grid.html if empty).")
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
