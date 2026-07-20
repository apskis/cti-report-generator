#!/usr/bin/env python3
"""
Diagnostic script to show what product names are being extracted from Rapid7 data.
This helps verify that Rapid7 technology detection is working correctly.
"""

import asyncio
import os
import sys
from collections import Counter

# Run from project root
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")

# Import what we need
from src.collectors.registry import collect_all
from src.core.config import azure_config
from src.core.keyvault import get_all_api_keys


async def diagnose_rapid7_products():
    """Show what products Rapid7 is detecting in your environment."""

    print("\n" + "=" * 70)
    print("RAPID7 PRODUCT DETECTION DIAGNOSTIC")
    print("=" * 70)

    # Get credentials from Azure Key Vault
    print("\n[*] Connecting to Azure Key Vault...")
    try:
        vault_url = azure_config.get_key_vault_url()
        credentials = get_all_api_keys(vault_url)
        print("[+] Credentials retrieved")
    except Exception as e:
        print(f"\n[-] Failed to load credentials: {e}")
        return

    # Collect data
    print("\n[*] Collecting data from all sources (focusing on Rapid7 scans)...")
    collector_results_dict = await collect_all(credentials, report_type="weekly")

    # Find Rapid7-Scans result
    rapid7_scan_result = collector_results_dict.get("Rapid7-Scans")
    if not rapid7_scan_result or not rapid7_scan_result.success:
        print("\n[-] No Rapid7 scan data found or collection failed")
        return

    rapid7_scan_data = rapid7_scan_result.data
    print(f"[+] Found {len(rapid7_scan_data)} CVE exposure records from Rapid7 scans")

    # Extract product names from titles
    product_names = []
    cve_to_product = {}

    for record in rapid7_scan_data:
        title = record.get("title", "")
        cve_id = record.get("cve_id", "")
        exposure = record.get("exposure", "")

        if title:
            # Clean the title to extract product name (same logic as threat_analyst.py)
            import re

            cleaned = re.split(r"\s*:\s*CVE-\d{4}-\d+", title)[0].strip()
            if cleaned and len(cleaned) > 2:
                product = cleaned
            else:
                product = title.split(":")[0].strip() if ":" in title else title

            product_names.append(product)
            cve_to_product[cve_id] = {"product": product, "exposure": exposure, "full_title": title}

    # Show statistics
    print("\n[*] Product Statistics:")
    print(f"   Total unique products detected: {len(set(product_names))}")

    # Count products
    product_counts = Counter(product_names)

    print("\n[*] Top 15 Products by CVE Count:")
    print("-" * 70)
    for product, count in product_counts.most_common(15):
        print(f"   {product:<50} {count:>3} CVEs")

    # Check for WordPress specifically
    wordpress_products = [p for p in product_names if "wordpress" in p.lower()]
    if wordpress_products:
        print("\n[!] WordPress Products Found:")
        print("-" * 70)
        wordpress_counts = Counter(wordpress_products)
        for product, count in wordpress_counts.most_common():
            print(f"   {product:<50} {count:>3} CVEs")
        print("\n   [+] These WordPress products ARE in your environment (detected by Rapid7)")
    else:
        print("\n[+] No WordPress products detected in environment")
        print("   (This means WordPress is NOT in your scanned assets)")

    # Show sample of all detected products
    print("\n[*] All Detected Products (first 30):")
    print("-" * 70)
    unique_products = sorted(set(product_names))[:30]
    for product in unique_products:
        print(f"   * {product}")

    if len(unique_products) < len(set(product_names)):
        remaining = len(set(product_names)) - len(unique_products)
        print(f"   ... and {remaining} more products")

    # Show a few example CVE mappings
    print("\n[*] Sample CVE -> Product Mappings:")
    print("-" * 70)
    for cve_id, info in list(cve_to_product.items())[:5]:
        print(f"\n   CVE: {cve_id}")
        print(f"   Product: {info['product']}")
        print(f"   Exposure: {info['exposure']}")
        print(f"   Full Title: {info['full_title'][:80]}...")

    print("\n" + "=" * 70)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(diagnose_rapid7_products())
