"""
Intel471 API Connection Test Script
Run this to verify your credentials work before integrating into the main system.

Usage:
    python test_intel471.py your_email@company.com your_api_key
"""

import asyncio
import sys
import aiohttp  # type: ignore
from datetime import datetime


async def test_connection(email: str, api_key: str):
    """Test Intel471 API connectivity."""
    
    print("=" * 60)
    print("Intel471 API Connection Test")
    print("=" * 60)
    
    base_url = "https://api.intel471.com/v1"
    auth = aiohttp.BasicAuth(email, api_key)
    
    async with aiohttp.ClientSession() as session:
        # Test 1: Check reports endpoint
        print("\n[1] Testing /reports endpoint...")
        try:
            async with session.get(
                f"{base_url}/reports",
                auth=auth,
                params={
                    "count": 3,
                    "from": "7day",  # Using string format
                    "v": "1.20.0"
                }
            ) as response:
                print(f"    Status: {response.status}")
                
                if response.status == 200:
                    data = await response.json()
                    total = data.get("reportTotalCount", 0)
                    reports = data.get("reports", [])
                    
                    print(f"    ✓ SUCCESS: Found {total} total reports")
                    print(f"    ✓ Retrieved {len(reports)} sample reports")
                    
                    if reports:
                        print("\n    Sample report structure:")
                        sample = reports[0]
                        print(f"      - uid: {sample.get('uid', 'N/A')[:30]}...")
                        print(f"      - subject: {sample.get('subject', 'N/A')[:50]}...")
                        print(f"      - documentType: {sample.get('documentType', 'N/A')}")
                        print(f"      - actorHandle: {sample.get('actorHandle', 'N/A')}")
                        print(f"      - tags: {sample.get('tags', [])}")
                        
                        created = sample.get('created', 0)
                        if created:
                            created_dt = datetime.fromtimestamp(created / 1000)
                            print(f"      - created: {created_dt.isoformat()}")
                        
                elif response.status == 401:
                    text = await response.text()
                    print(f"    ✗ AUTHENTICATION FAILED")
                    print(f"    Response: {text[:200]}")
                    print("\n    Check that:")
                    print("    1. Your email address is correct")
                    print("    2. Your API key is correct (from Intel471 Portal > API)")
                    
                elif response.status == 403:
                    print(f"    ✗ ACCESS FORBIDDEN")
                    print("    API access may not be enabled on your account.")
                    print("    Contact Intel471 support: support@intel471.com")
                    
                else:
                    text = await response.text()
                    print(f"    ✗ Unexpected status: {response.status}")
                    print(f"    Response: {text[:300]}")
                    
        except Exception as e:
            print(f"    ✗ ERROR: {e}")
        
        # Test 2: Check indicators endpoint
        print("\n[2] Testing /indicators endpoint...")
        try:
            async with session.get(
                f"{base_url}/indicators",
                auth=auth,
                params={
                    "count": 3,
                    "from": "7day",
                    "v": "1.20.0"
                }
            ) as response:
                print(f"    Status: {response.status}")
                
                if response.status == 200:
                    data = await response.json()
                    total = data.get("indicatorTotalCount", 0)
                    indicators = data.get("indicators", [])
                    
                    print(f"    ✓ SUCCESS: Found {total} total indicators")
                    print(f"    ✓ Retrieved {len(indicators)} sample indicators")
                    
                    if indicators:
                        print("\n    Sample indicator structure:")
                        sample = indicators[0]
                        sample_data = sample.get("data", {})
                        
                        print(f"      - uid: {sample.get('uid', 'N/A')[:30]}...")
                        print(f"      - indicator_type: {sample_data.get('indicator_type', 'N/A')}")
                        print(f"      - confidence: {sample_data.get('confidence', 'N/A')}")
                        
                        threat = sample_data.get("threat", {})
                        threat_data = threat.get("data", {})
                        print(f"      - threat.type: {threat.get('type', 'N/A')}")
                        print(f"      - malware_family: {threat_data.get('family', 'N/A')}")
                        
                        last_updated = sample.get("last_updated", 0)
                        if last_updated:
                            updated_dt = datetime.fromtimestamp(last_updated / 1000)
                            print(f"      - last_updated: {updated_dt.isoformat()}")
                            
                elif response.status == 401:
                    print(f"    ✗ AUTHENTICATION FAILED (same as reports)")
                    
                elif response.status == 403:
                    print(f"    ⚠ Malware Intelligence product may not be in your subscription")
                    print("    This is separate from Adversary Intelligence (reports)")
                    
                else:
                    text = await response.text()
                    print(f"    ⚠ Status: {response.status}")
                    print(f"    Response: {text[:200]}")
                    
        except Exception as e:
            print(f"    ✗ ERROR: {e}")
        
        # Test 3: Check with healthcare tags
        print("\n[3] Testing healthcare/biotech tag filter...")
        healthcare_tags = ["Healthcare", "Life Sciences", "Pharmaceutical"]
        
        for tag in healthcare_tags:
            try:
                async with session.get(
                    f"{base_url}/reports",
                    auth=auth,
                    params={
                        "reportTag": tag,
                        "count": 1,
                        "from": "30day",
                        "v": "1.20.0"
                    }
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        total = data.get("reportTotalCount", 0)
                        print(f"    - Tag '{tag}': {total} reports found")
                    else:
                        print(f"    - Tag '{tag}': Error {response.status}")
            except Exception as e:
                print(f"    - Tag '{tag}': Error {e}")
    
    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python test_intel471.py <email> <api_key>")
        print("\nExample:")
        print("  python test_intel471.py user@company.com abc123...")
        sys.exit(1)
    
    email = sys.argv[1]
    api_key = sys.argv[2]
    
    asyncio.run(test_connection(email, api_key))