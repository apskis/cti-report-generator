#!/usr/bin/env python3
"""Diagnostic: find which Intel471 endpoint serves the Breach Alerts feed.

The weekly report collects 0 breach alerts even though the Titan portal shows thousands.
This probe tries the candidate endpoints with your real credentials and prints, for each,
the HTTP status, the top-level JSON keys, how many items came back, and a sample record —
so we can point the collector at the right one.

Run locally (needs Azure login for Key Vault):
    python scripts/probe_intel471_breach.py
"""

import asyncio
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aiohttp

BASE = "https://api.intel471.com/v1"
API_VERSION = "1.20.0"


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


async def _probe(session, auth, path, params, label=""):
    url = f"{BASE}{path}"
    tag = f"{path} [{label}]" if label else path
    try:
        async with session.get(url, auth=auth, params=params) as resp:
            status = resp.status
            body_text = await resp.text()
    except Exception as e:
        print(f"\n### GET {tag}\n    ERROR: {type(e).__name__}: {e}")
        return

    print(f"\n### GET {tag}  params={params}")
    print(f"    status: {status}")
    if status != 200:
        # The error body usually names the missing/required parameter.
        print(f"    body: {body_text[:400]}")
        return
    try:
        data = json.loads(body_text)
    except Exception:
        print(f"    non-JSON body: {body_text[:300]}")
        return
    print(f"    top-level keys: {list(data.keys())}")
    for key, val in data.items():
        if isinstance(val, list):
            print(f"    '{key}': {len(val)} items")
            if val and isinstance(val[0], dict):
                sample = val[0]
                print(f"      sample record keys: {list(sample.keys())}")
                for f in ("subject", "title", "documentType", "documentFamily", "type", "name",
                          "victims", "entities", "actor_or_group_str", "confidence", "activity"):
                    if f in sample:
                        print(f"        {f}: {json.dumps(sample[f])[:200]}")


async def main():
    from src.core.config import azure_config
    from src.core.keyvault import get_all_api_keys

    creds = get_all_api_keys(azure_config.get_key_vault_url())
    email = creds.get("intel471_email")
    api_key = creds.get("intel471_key")
    if not email or not api_key:
        print("Missing Intel471 creds (intel471_email / intel471_key) from Key Vault.")
        return
    auth = aiohttp.BasicAuth(email, api_key)

    end = datetime.utcnow()
    start = end - timedelta(days=10)
    win = {"from": _ms(start), "until": _ms(end), "count": 5, "v": API_VERSION}

    print(f"Window: {start.date()} .. {end.date()}  (last 10 days)")
    async with aiohttp.ClientSession() as s:
        # /breachAlerts returned 412 last time — try param variants to find what it requires.
        await _probe(s, auth, "/breachAlerts", {**win}, "from/until")
        await _probe(s, auth, "/breachAlerts", {"count": 5, "v": API_VERSION}, "count only")
        await _probe(s, auth, "/breachAlerts", {**win, "sort": "latest"}, "sort=latest")
        await _probe(s, auth, "/breachAlerts",
                     {"lastUpdatedFrom": _ms(start), "count": 5, "v": API_VERSION}, "lastUpdatedFrom")
        await _probe(s, auth, "/breachAlerts", {"breachAlert": "*", "count": 5, "v": API_VERSION}, "breachAlert=*")
        # For comparison: what documentTypes appear in /reports? (are breach alerts in there?)
        await _scan_report_doctypes(s, auth, {**win, "count": 50})


async def _scan_report_doctypes(session, auth, params):
    url = f"{BASE}/reports"
    async with session.get(url, auth=auth, params=params) as resp:
        if resp.status != 200:
            print(f"\n### /reports documentType scan -> status {resp.status}")
            return
        data = await resp.json()
    from collections import Counter

    reports = data.get("reports", [])
    counts = Counter(r.get("documentType", "?") for r in reports)
    print(f"\n### /reports documentType histogram ({len(reports)} reports):")
    for dtype, n in counts.most_common():
        print(f"    {dtype}: {n}")


if __name__ == "__main__":
    asyncio.run(main())
