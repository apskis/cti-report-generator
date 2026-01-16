import aiohttp  # type: ignore
import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict
import json

logger = logging.getLogger(__name__)


async def get_nvd_cves(api_key: str) -> List[Dict]:
    """
    Fetch CVEs from NVD API (last 7 days, CRITICAL and HIGH only).
    
    Args:
        api_key: NVD API key
        
    Returns:
        List of CVE dictionaries
    """
    logger.info("Fetching CVEs from NVD API")
    
    try:
        # Calculate date range (last 7 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        # Format dates for NVD API (ISO 8601 format)
        start_date_str = start_date.strftime("%Y-%m-%dT00:00:00.000")
        end_date_str = end_date.strftime("%Y-%m-%dT23:59:59.999")
        
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        params = {
            "pubStartDate": start_date_str,
            "pubEndDate": end_date_str,
            "resultsPerPage": 100
        }
        
        headers = {
            "apiKey": api_key
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    cves = []
                    
                    for item in data.get("vulnerabilities", []):
                        cve = item.get("cve", {})
                        cve_id = cve.get("id", "")
                        
                        # Extract CVSS score and severity
                        metrics = cve.get("metrics", {})
                        cvss_score = 0
                        severity = "UNKNOWN"
                        
                        # Try CVSS v3.1 first, then v3.0, then v2.0
                        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                            cvss_score = cvss_data.get("baseScore", 0)
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                            cvss_score = cvss_data.get("baseScore", 0)
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                            cvss_score = cvss_data.get("baseScore", 0)
                            # Convert v2 score to severity
                            if cvss_score >= 9.0:
                                severity = "CRITICAL"
                            elif cvss_score >= 7.0:
                                severity = "HIGH"
                        
                        # Only include CRITICAL and HIGH severity
                        if severity in ["CRITICAL", "HIGH"]:
                            # Extract description
                            descriptions = cve.get("descriptions", [])
                            description = ""
                            for desc in descriptions:
                                if desc.get("lang") == "en":
                                    description = desc.get("value", "")
                                    break
                            
                            # Get published date
                            published = cve.get("published", "")
                            
                            cves.append({
                                "cve_id": cve_id,
                                "description": description,
                                "cvss_score": cvss_score,
                                "severity": severity,
                                "published_date": published,
                                "exploited": False  # NVD doesn't have exploitation status
                            })
                    
                    logger.info(f"Retrieved {len(cves)} CRITICAL/HIGH CVEs from NVD")
                    return cves
                else:
                    logger.error(f"NVD API returned status {response.status}")
                    return []
                    
    except Exception as e:
        logger.error(f"Error fetching NVD CVEs: {e}", exc_info=True)
        return []


async def get_intel471_data(email: str, api_key: str) -> List[Dict]:
    """
    Fetch threat intelligence from Intel471 (last 7 days).
    
    Args:
        email: Intel471 login email
        api_key: Intel471 API key
        
    Returns:
        List of threat intelligence dictionaries
    """
    logger.info("Fetching data from Intel471 API")
    
    try:
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        base_url = "https://api.intel471.com/v1"
        
        # Intel471 uses Basic Authentication with email as username and API key as password
        auth = aiohttp.BasicAuth(email, api_key)
        
        threats = []
        
        async with aiohttp.ClientSession() as session:
            # Fetch reports
            reports_url = f"{base_url}/reports"
            params = {
                "from": int(start_date.timestamp()),
                "until": int(end_date.timestamp()),
                "count": 50
            }
            
            async with session.get(reports_url, auth=auth, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for report in data.get("reports", []):
                        # Filter for biotech/genomics/healthcare keywords
                        text = report.get("text", "").lower()
                        title = report.get("title", "").lower()
                        
                        keywords = ["biotech", "genomics", "healthcare", "hospital", "medical", 
                                   "pharmaceutical", "life sciences", "research"]
                        
                        if any(keyword in text or keyword in title for keyword in keywords):
                            threats.append({
                                "threat_actor": report.get("actor", {}).get("name", "Unknown"),
                                "threat_type": report.get("type", "Report"),
                                "confidence": report.get("confidence", "Medium"),
                                "summary": report.get("title", "")[:500],
                                "date": report.get("released", "")
                            })
                    
                    logger.info(f"Retrieved {len(threats)} items from Intel471 reports")
                else:
                    logger.error(f"Intel471 reports API returned status {response.status}")
                    response_text = await response.text()
                    logger.error(f"Intel471 response: {response_text[:500]}")
            
            # Fetch indicators
            indicators_url = f"{base_url}/indicators"
            
            async with session.get(indicators_url, auth=auth, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for indicator in data.get("indicators", [])[:20]:
                        threats.append({
                            "threat_actor": indicator.get("actor", "Unknown"),
                            "threat_type": "Indicator",
                            "confidence": indicator.get("confidence", "Medium"),
                            "summary": f"{indicator.get('type', 'Unknown')}: {indicator.get('value', '')}",
                            "date": indicator.get("last_seen", "")
                        })
                    
                    logger.info(f"Retrieved {len(threats)} total items from Intel471")
                else:
                    logger.error(f"Intel471 indicators API returned status {response.status}")
        
        return threats
        
    except Exception as e:
        logger.error(f"Error fetching Intel471 data: {e}", exc_info=True)
        return []


async def get_crowdstrike_data(client_id: str, client_secret: str, base_url: str = "https://api.crowdstrike.com") -> List[Dict]:
    """
    Fetch APT intelligence from CrowdStrike (OAuth2 authentication).
    
    Args:
        client_id: CrowdStrike OAuth2 client ID
        client_secret: CrowdStrike OAuth2 client secret
        base_url: CrowdStrike API base URL (varies by region)
        
    Returns:
        List of APT activity dictionaries
    """
    logger.info(f"Fetching data from CrowdStrike API: {base_url}")
    
    try:
        async with aiohttp.ClientSession() as session:
            # Step 1: Get OAuth2 token
            token_url = f"{base_url}/oauth2/token"
            token_data = {
                "client_id": client_id,
                "client_secret": client_secret
            }
            
            logger.info(f"Requesting OAuth token from: {token_url}")
            async with session.post(token_url, data=token_data) as response:
                logger.info(f"OAuth token response status: {response.status}")
                
                if response.status == 201:
                    token_response = await response.json()
                    access_token = token_response.get("access_token")
                    
                    if not access_token:
                        logger.error("Failed to obtain CrowdStrike access token")
                        return []
                    
                    logger.info("Successfully obtained CrowdStrike access token")
                    
                    headers = {
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json"
                    }
                    
                    apt_data = []
                    
                    # Step 2: Fetch actors
                    actors_url = f"{base_url}/intel/combined/actors/v1"
                    params = {
                        "limit": 50,
                        "sort": "last_modified_date.desc"
                    }
                    
                    logger.info(f"Fetching actors from: {actors_url}")
                    async with session.get(actors_url, headers=headers, params=params) as actor_response:
                        logger.info(f"Actors API response status: {actor_response.status}")
                        
                        if actor_response.status == 200:
                            actors = await actor_response.json()
                            
                            for actor in actors.get("resources", []):
                                # Filter for tech/healthcare/life sciences
                                target_industries = actor.get("target_industries", [])
                                relevant = any(ind in ["Technology", "Healthcare", "Pharmaceutical", 
                                                      "Life Sciences", "Biotechnology"] 
                                             for ind in target_industries)
                                
                                if relevant or not target_industries:  # Include if no industry specified
                                    apt_data.append({
                                        "actor_name": actor.get("name", "Unknown"),
                                        "country": actor.get("origins", [{}])[0].get("value", "Unknown") if actor.get("origins") else "Unknown",
                                        "motivations": actor.get("motivations", []),
                                        "ttps": actor.get("kill_chain", [])[:5],
                                        "target_industries": target_industries,
                                        "last_activity": actor.get("last_modified_date", "")
                                    })
                            
                            logger.info(f"Retrieved {len(apt_data)} actors from CrowdStrike")
                        else:
                            response_text = await actor_response.text()
                            logger.error(f"CrowdStrike actors API returned status {actor_response.status}: {response_text[:500]}")
                    
                    # Step 3: Fetch indicators
                    indicators_url = f"{base_url}/intel/combined/indicators/v1"
                    params = {
                        "limit": 50,
                        "sort": "_marker.desc"
                    }
                    
                    logger.info(f"Fetching indicators from: {indicators_url}")
                    async with session.get(indicators_url, headers=headers, params=params) as indicator_response:
                        logger.info(f"Indicators API response status: {indicator_response.status}")
                        
                        if indicator_response.status == 200:
                            indicators = await indicator_response.json()
                            
                            # Add high-confidence indicators to apt_data
                            for indicator in indicators.get("resources", [])[:10]:
                                if indicator.get("malicious_confidence") in ["high", "medium"]:
                                    apt_data.append({
                                        "actor_name": (indicator.get("actors") or [None])[0] if indicator.get("actors") else "Unknown",
                                        "country": "Unknown",
                                        "motivations": ["Malicious Activity"],
                                        "ttps": [indicator.get("type", "Unknown")],
                                        "target_industries": [],
                                        "indicator": indicator.get("indicator", ""),
                                        "last_activity": indicator.get("last_updated", "")
                                    })
                            
                            logger.info(f"Retrieved total of {len(apt_data)} items from CrowdStrike")
                        else:
                            response_text = await indicator_response.text()
                            logger.error(f"CrowdStrike indicators API returned status {indicator_response.status}: {response_text[:500]}")
                    
                    return apt_data
                else:
                    response_text = await response.text()
                    logger.error(f"CrowdStrike OAuth token request returned status {response.status}: {response_text[:500]}")
                    return []
                    
    except Exception as e:
        logger.error(f"Error fetching CrowdStrike data: {e}", exc_info=True)
        return []


async def get_threatq_data(api_key: str, threatq_url: str) -> List[Dict]:
    """
    Fetch indicators from ThreatQ.
    
    Args:
        api_key: ThreatQ API token
        threatq_url: ThreatQ instance URL (e.g., https://company.threatq.com)
        
    Returns:
        List of indicator dictionaries
    """
    if not threatq_url:
        logger.info("ThreatQ URL not provided, skipping ThreatQ data collection")
        return []
    
    logger.info("Fetching data from ThreatQ API")
    
    try:
        # Ensure URL has proper format
        if not threatq_url.startswith("http"):
            threatq_url = f"https://{threatq_url}"
        
        api_url = f"{threatq_url}/api"
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        indicators = []
        
        async with aiohttp.ClientSession() as session:
            # Fetch high-priority indicators
            indicators_url = f"{api_url}/indicators"
            params = {
                "limit": 100,
                "status": "Active",
                "sort": "-score"
            }
            
            async with session.get(indicators_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for indicator in data.get("data", []):
                        score = indicator.get("score", 0)
                        
                        # Only include high-score indicators (>= 7)
                        if score >= 7:
                            indicators.append({
                                "indicator_type": indicator.get("type", {}).get("name", "Unknown"),
                                "status": indicator.get("status", {}).get("name", "Unknown"),
                                "score": score,
                                "value": indicator.get("value", ""),
                                "last_seen": indicator.get("updated_at", "")
                            })
                    
                    logger.info(f"Retrieved {len(indicators)} high-priority indicators from ThreatQ")
                else:
                    logger.error(f"ThreatQ API returned status {response.status}")
        
        return indicators
        
    except Exception as e:
        logger.error(f"Error fetching ThreatQ data: {e}", exc_info=True)
        return []


async def get_rapid7_data(api_key: str, region: str = "us") -> List[Dict]:
    """
    Fetch vulnerability data from Rapid7 InsightVM.
    
    Args:
        api_key: Rapid7 API key
        region: Rapid7 region (us, eu, ca, au, ap)
        
    Returns:
        List of vulnerability dictionaries
    """
    logger.info("Fetching data from Rapid7 API")
    
    try:
        # Determine base URL based on region
        base_url = f"https://{region}.api.insight.rapid7.com"
        
        headers = {
            "X-Api-Key": api_key,
            "Content-Type": "application/json"
        }
        
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            # Fetch vulnerability data
            vuln_url = f"{base_url}/vm/v4/integration/vulnerabilities"
            params = {
                "size": 100,
                "sort": "riskScore,DESC"
            }
            
            async with session.get(vuln_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for vuln in data.get("resources", []):
                        severity = vuln.get("severity", "")
                        
                        # Only include Critical and Severe vulnerabilities
                        if severity in ["Critical", "Severe"]:
                            # Get CVE IDs
                            cve_ids = [ref.get("id") for ref in vuln.get("references", []) 
                                      if ref.get("source") == "CVE"]
                            
                            vulnerabilities.append({
                                "vulnerability_id": vuln.get("id", ""),
                                "title": vuln.get("title", ""),
                                "severity": severity,
                                "risk_score": vuln.get("riskScore", 0),
                                "cve_ids": cve_ids,
                                "published": vuln.get("published", ""),
                                "exploits": vuln.get("exploits", 0) > 0
                            })
                    
                    # Get asset count
                    assets_url = f"{base_url}/vm/v4/integration/assets"
                    async with session.get(assets_url, headers=headers) as assets_response:
                        if assets_response.status == 200:
                            assets_data = await assets_response.json()
                            asset_count = assets_data.get("page", {}).get("totalResources", 0)
                        else:
                            asset_count = 0
                    
                    # Calculate summary statistics
                    summary = {
                        "asset_count": asset_count,
                        "vulnerability_count": len(vulnerabilities),
                        "critical_count": sum(1 for v in vulnerabilities if v["severity"] == "Critical"),
                        "exploitable_count": sum(1 for v in vulnerabilities if v.get("exploits", False)),
                        "average_risk_score": sum(v["risk_score"] for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0,
                        "vulnerabilities": vulnerabilities[:20]  # Limit to top 20
                    }
                    
                    logger.info(f"Retrieved {len(vulnerabilities)} Critical/Severe vulnerabilities from Rapid7")
                    return [summary]  # Return as single summary object
                else:
                    logger.error(f"Rapid7 API returned status {response.status}")
                    return []
                    
    except Exception as e:
        logger.error(f"Error fetching Rapid7 data: {e}", exc_info=True)
        return []