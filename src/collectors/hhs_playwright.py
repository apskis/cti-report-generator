"""Browser-driven CSV export from the HHS OCR breach portal.

The portal is a JavaScript-rendered PrimeFaces app — the data grid and its CSV export only
exist after client-side JS runs, so raw HTTP can't reach them. This drives a headless
Chromium (Playwright) to open the portal, navigate to the HIPAA breach reports grid, click
the CSV export, and capture the downloaded file.

Playwright is an OPTIONAL dependency (guarded import). If it isn't installed, this returns
``None`` and the collector degrades gracefully. Install with::

    pip install playwright
    playwright install chromium
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from src.collectors.hhs_fetch import looks_like_hhs_csv

logger = logging.getLogger(__name__)


async def _open_report_grid(page) -> bool:
    """Click through to the HIPAA breach reports grid (breach_report_hip.jsf)."""
    for label, getter in (
        ("role=link", lambda: page.get_by_role("link", name=re.compile("View HIPAA Breach Reports", re.I))),
        ("text", lambda: page.get_by_text("View HIPAA Breach Reports", exact=False)),
    ):
        try:
            await getter().first.click(timeout=8000)
            try:
                await page.wait_for_load_state("networkidle", timeout=30000)
            except Exception:
                pass
            await page.wait_for_timeout(2000)  # let the lazy grid settle
            logger.info(f"HHS browser: opened grid via {label}")
            return True
        except Exception as e:
            logger.info(f"HHS browser: grid nav via {label} failed: {e}")
    logger.info("HHS browser: could not open the reports grid")
    return False


async def _click_export_and_capture(page, timeout_ms: int) -> str | None:
    """Click the CSV export icon and return the downloaded file's text (if it's CSV).

    The export is an <img alt="CSV" title="Export as CSV"> inside a JSF command anchor.
    Its element id is auto-generated (j_idt*) and unstable, so target the stable
    title/alt via Playwright's by-title / by-alt-text locators (the by-attribute locator
    family that works even where the CSS selector engine / page.evaluate hit an injected-
    script bug). Clicking the icon bubbles to the anchor's onclick -> JSF export -> download.
    """
    getters = (
        ("title=Export as CSV", lambda: page.get_by_title("Export as CSV")),
        ("alt=CSV", lambda: page.get_by_alt_text("CSV", exact=True)),
    )
    for label, getter in getters:
        try:
            loc = getter().first
        except Exception as e:
            logger.info(f"HHS browser: export locator {label} unavailable: {e}")
            continue
        try:
            async with page.expect_download(timeout=timeout_ms) as dl_info:
                await loc.click(timeout=10000)
            download = await dl_info.value
            path = await download.path()
            if not path:
                continue
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            if looks_like_hhs_csv(text):
                logger.info(f"HHS browser: CSV captured via {label} ({len(text)} bytes)")
                return text
            logger.info(f"HHS browser: {label} downloaded a non-CSV file; trying next")
        except Exception as e:
            logger.info(f"HHS browser: export via {label} failed: {e}")
    return None


async def fetch_hhs_csv_via_browser(portal_url: str, *, headless: bool = True, timeout_ms: int = 60000) -> str | None:
    """Drive a headless browser to export the HHS breach report as CSV. Returns CSV or None."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.info(
            "playwright not installed; skipping browser-based HHS export "
            "(pip install playwright && playwright install chromium)"
        )
        return None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            try:
                context = await browser.new_context(accept_downloads=True)
                page = await context.new_page()
                await page.goto(portal_url, wait_until="networkidle", timeout=timeout_ms)
                await _open_report_grid(page)
                return await _click_export_and_capture(page, timeout_ms)
            finally:
                await browser.close()
    except Exception as e:
        logger.info(f"HHS browser export failed: {e}")
        return None
