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


async def _probe(session, auth, path, params):
    url = f"{BASE}{path}"
    try:
        async with session.get(url, auth=auth, params=params) as resp:
            status = resp.status
            try:
                data = await resp.json()
            except Exception:
                data = {"_non_json_body": (await resp.text())[:300]}
    except Exception as e:
        print(f"\n### GET {path}  params={params}\n    ERROR: {type(e).__name__}: {e}")
        return

    print(f"\n### GET {path}  params={params}")
    print(f"    status: {status}")
    if not isinstance(data, dict):
        print(f"    body (non-dict): {str(data)[:300]}")
        return
    print(f"    top-level keys: {list(data.keys())}")
    # Find the first list-valued key (that's usually the records array)
    for key, val in data.items():
        if isinstance(val, list):
            print(f"    '{key}': {len(val)} items")
            if val:
                sample = val[0]
                keys = list(sample.keys()) if isinstance(sample, dict) else type(sample).__name__
                print(f"      sample record keys: {keys}")
                # Show a few fields likely to name the victim org / type / date
                if isinstance(sample, dict):
                    for f in ("subject", "title", "documentType", "type", "name", "entity",
                              "actor_or_group_str", "victim", "confidence", "activity"):
                        if f in sample:
                            print(f"        {f}: {json.dumps(sample[f])[:120]}")


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
        # Candidate 1: dedicated breach-alerts list endpoint (most likely).
        await _probe(s, auth, "/breachAlerts", win)
        # Candidate 2: what the collector currently uses (watcher alerts).
        await _probe(s, auth, "/alerts", {**win, "documentType": "BREACH ALERT"})
        # Candidate 3: reports endpoint, unfiltered — inspect the documentType values present.
        await _probe(s, auth, "/reports", win)


if __name__ == "__main__":
    asyncio.run(main())
