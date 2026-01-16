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
    
    Based on Intel471 Titan API v1.20.0 Swagger Specification.
    Key fixes applied:
    - Timestamps converted to milliseconds (multiply by 1000)
    - Field names corrected to match API response schema
    - Indicator nested structure properly handled
    
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
            # =====================
            # Fetch Reports
            # =====================
            reports_url = f"{base_url}/reports"
            
            # CRITICAL: Intel471 uses MILLISECONDS, not seconds!
            # Alternative: use string format like "7day"
            params = {
                "from": int(start_date.timestamp() * 1000),  # Convert to milliseconds
                "until": int(end_date.timestamp() * 1000),   # Convert to milliseconds
                "count": 50,
                "v": "1.20.0"  # Pin API version for consistency
            }
            
            async with session.get(reports_url, auth=auth, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for report in data.get("reports", []):
                        # CORRECTED field names based on SimpleReportSchema:
                        # - "subject" not "title"
                        # - "actorHandle" not "actor.name"
                        # - "documentType" not "type"
                        # Note: "rawText" only available in /reports/{uid} endpoint
                        
                        subject = report.get("subject", "").lower()
                        tags = [t.lower() for t in report.get("tags", [])]
                        
                        # Keywords for biotech/genomics/healthcare filtering
                        keywords = [
                            "biotech", "genomics", "healthcare", "hospital", "medical",
                            "pharmaceutical", "life sciences", "research", "clinical",
                            "patient", "health", "laboratory", "diagnostics"
                        ]
                        
                        # Check subject and tags for relevance
                        is_relevant = (
                            any(keyword in subject for keyword in keywords) or
                            any(keyword in tag for tag in tags for keyword in keywords)
                        )
                        
                        if is_relevant:
                            # Extract actor handle if present
                            actor_handle = report.get("actorHandle", "Unknown")
                            
                            # Also check actorSubjectOfReport for actor names
                            actor_subjects = report.get("actorSubjectOfReport", [])
                            if actor_subjects and actor_handle == "Unknown":
                                actor_handle = actor_subjects[0].get("handle", "Unknown")
                            
                            # Convert timestamp from milliseconds to ISO format
                            created_ms = report.get("created", 0)
                            created_date = ""
                            if created_ms:
                                created_date = datetime.fromtimestamp(created_ms / 1000).isoformat()
                            
                            # Map admiralty code to confidence level
                            admiralty = report.get("admiraltyCode", "")
                            confidence_map = {
                                "A": "Confirmed",
                                "B": "High",
                                "C": "Medium",
                                "D": "Low",
                                "E": "Very Low",
                                "F": "Cannot be judged"
                            }
                            confidence = confidence_map.get(admiralty[:1], "Medium") if admiralty else "Medium"
                            
                            threats.append({
                                "source": "Intel471",
                                "threat_actor": actor_handle,
                                "threat_type": report.get("documentType", "Report"),
                                "confidence": confidence,
                                "summary": report.get("subject", "")[:500],
                                "date": created_date,
                                "tags": report.get("tags", []),
                                "motivation": report.get("motivation", []),
                                "portal_url": report.get("portalReportUrl", ""),
                                "uid": report.get("uid", "")
                            })
                    
                    logger.info(f"Retrieved {len(threats)} relevant items from Intel471 reports")
                else:
                    logger.error(f"Intel471 reports API returned status {response.status}")
                    response_text = await response.text()
                    logger.error(f"Intel471 response: {response_text[:500]}")
            
            # =====================
            # Fetch Indicators
            # =====================
            indicators_url = f"{base_url}/indicators"
            
            # Indicators use same timestamp format
            indicator_params = {
                "from": int(start_date.timestamp() * 1000),
                "until": int(end_date.timestamp() * 1000),
                "count": 20,
                "v": "1.20.0"
            }
            
            async with session.get(indicators_url, auth=auth, params=indicator_params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for indicator in data.get("indicators", []):
                        # CORRECTED: Indicators have nested "data" structure
                        # See IndicatorSearchResponse schema in swagger
                        
                        indicator_data = indicator.get("data", {})
                        threat_info = indicator_data.get("threat", {})
                        threat_data = threat_info.get("data", {})
                        
                        # Get indicator details
                        indicator_type = indicator_data.get("indicator_type", "Unknown")
                        indicator_values = indicator_data.get("indicator_data", {})
                        
                        # Extract the actual indicator value based on type
                        value = ""
                        if indicator_type == "url":
                            value = indicator_values.get("url", "")
                        elif indicator_type == "file":
                            value = indicator_values.get("md5", "") or indicator_values.get("sha256", "")
                        elif indicator_type == "ipv4":
                            value = indicator_values.get("ipv4", "")
                        elif indicator_type == "domain":
                            value = indicator_values.get("domain", "")
                        else:
                            # Generic fallback
                            value = str(indicator_values)[:100] if indicator_values else ""
                        
                        # Get last updated timestamp (in milliseconds)
                        last_updated_ms = indicator.get("last_updated", 0)
                        last_updated_date = ""
                        if last_updated_ms:
                            last_updated_date = datetime.fromtimestamp(last_updated_ms / 1000).isoformat()
                        
                        # Get malware family from threat data
                        malware_family = threat_data.get("family", "Unknown")
                        
                        threats.append({
                            "source": "Intel471",
                            "threat_actor": malware_family,  # Using malware family as identifier
                            "threat_type": f"Indicator ({indicator_type})",
                            "confidence": indicator_data.get("confidence", "Medium"),
                            "summary": f"{indicator_type.upper()}: {value}",
                            "date": last_updated_date,
                            "mitre_tactics": indicator_data.get("mitre_tactics", ""),
                            "indicator_uid": indicator.get("uid", "")
                        })
                    
                    logger.info(f"Retrieved {len(threats)} total items from Intel471")
                else:
                    logger.error(f"Intel471 indicators API returned status {response.status}")
                    response_text = await response.text()
                    logger.error(f"Intel471 indicators response: {response_text[:500]}")
        
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
    Fetch vulnerability data from Rapid7 InsightVM Cloud API V4.
    
    Uses POST /vm/v4/integration/vulnerabilities endpoint to retrieve
    all vulnerabilities that can be assessed, with CVE IDs for correlation.
    
    API Reference: https://help.rapid7.com/insightvm/en-us/api/integrations.html
    
    Args:
        api_key: Rapid7 Organization API key (from Insight Platform)
        region: Rapid7 region (us, us2, us3, eu, ca, au, ap)
        
    Returns:
        List containing vulnerability summary with CVE mappings
    """
    logger.info(f"Fetching data from Rapid7 InsightVM Cloud API (region: {region})")
    
    try:
        # Build base URL for the specified region
        # Format: https://{region}.api.insight.rapid7.com
        base_url = f"https://{region}.api.insight.rapid7.com"
        
        headers = {
            "X-Api-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        vulnerabilities = []
        all_cve_ids = set()  # Track unique CVEs for correlation
        
        async with aiohttp.ClientSession() as session:
            # =====================
            # Fetch Vulnerabilities via POST
            # =====================
            # POST /vm/v4/integration/vulnerabilities
            # Returns all vulnerabilities that can be assessed
            vuln_url = f"{base_url}/vm/v4/integration/vulnerabilities"
            
            # Request body with search criteria
            # Get vulnerabilities modified in the last 30 days for relevance
            from datetime import datetime, timedelta
            thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00Z")
            
            request_body = {
                "vulnerability": f"modified > {thirty_days_ago}"
            }
            
            # Query parameters for pagination
            params = {
                "size": 500,  # Max records per page
                "sort": "severity,DESC"  # Sort by severity descending
            }
            
            logger.info(f"Fetching vulnerabilities from: {vuln_url}")
            logger.info(f"Request body: {request_body}")
            
            async with session.post(vuln_url, headers=headers, json=request_body, params=params) as response:
                logger.info(f"Rapid7 vulnerabilities API response status: {response.status}")
                
                if response.status == 200:
                    data = await response.json()
                    
                    # Response structure: data, metadata, links
                    vuln_list = data.get("data", [])
                    metadata = data.get("metadata", {})
                    
                    total_resources = metadata.get("totalResources", 0)
                    logger.info(f"Total vulnerabilities available: {total_resources}")
                    logger.info(f"Retrieved {len(vuln_list)} vulnerabilities in this page")
                    
                    # Process each vulnerability
                    for vuln in vuln_list:
                        # Extract severity
                        severity = vuln.get("severity", "").upper()
                        
                        # Map severity levels
                        severity_map = {
                            "CRITICAL": "Critical",
                            "SEVERE": "Severe", 
                            "HIGH": "Severe",
                            "MODERATE": "Moderate",
                            "MEDIUM": "Moderate",
                            "LOW": "Low"
                        }
                        normalized_severity = severity_map.get(severity, severity)
                        
                        # Only include Critical and Severe vulnerabilities
                        if normalized_severity in ["Critical", "Severe"]:
                            # Extract CVE IDs
                            # V4 API stores CVEs in 'cves' array
                            cve_ids = vuln.get("cves", [])
                            
                            # Track all unique CVEs for correlation
                            all_cve_ids.update(cve_ids)
                            
                            # Get CVSS scores
                            cvss_v3 = vuln.get("cvss", {}).get("v3", {})
                            cvss_v2 = vuln.get("cvss", {}).get("v2", {})
                            cvss_score = cvss_v3.get("score", cvss_v2.get("score", 0))
                            
                            # Check for exploitability
                            # exploits and malwareKits can be lists or integers depending on API version
                            exploits = vuln.get("exploits", 0)
                            malware_kits = vuln.get("malwareKits", 0)
                            
                            # Handle if exploits/malwareKits are lists (contains exploit objects) or integers (count)
                            if isinstance(exploits, list):
                                exploits_count = len(exploits)
                            else:
                                exploits_count = exploits if isinstance(exploits, int) else 0
                                
                            if isinstance(malware_kits, list):
                                malware_kits_count = len(malware_kits)
                            else:
                                malware_kits_count = malware_kits if isinstance(malware_kits, int) else 0
                            
                            vulnerabilities.append({
                                "source": "Rapid7",
                                "vulnerability_id": vuln.get("id", ""),
                                "title": vuln.get("title", ""),
                                "description": vuln.get("description", {}).get("text", "")[:300] if isinstance(vuln.get("description"), dict) else str(vuln.get("description", ""))[:300],
                                "severity": normalized_severity,
                                "cvss_score": cvss_score,
                                "cve_ids": cve_ids,
                                "exploitable": exploits_count > 0 or malware_kits_count > 0,
                                "exploits_count": exploits_count,
                                "malware_kits_count": malware_kits_count,
                                "published": vuln.get("published", ""),
                                "modified": vuln.get("modified", ""),
                                "risk_score": vuln.get("riskScore", 0),
                                "categories": vuln.get("categories", [])
                            })
                    
                    # Sort by CVSS score descending
                    vulnerabilities.sort(key=lambda x: (x.get("cvss_score", 0), x.get("exploitable", False)), reverse=True)
                    
                    # Build summary for the report
                    summary = {
                        "source": "Rapid7",
                        "total_vulnerabilities_scanned": total_resources,
                        "critical_severe_count": len(vulnerabilities),
                        "unique_cve_count": len(all_cve_ids),
                        "all_cve_ids": list(all_cve_ids),  # For CVE correlation with threat intel
                        "critical_count": sum(1 for v in vulnerabilities if v["severity"] == "Critical"),
                        "severe_count": sum(1 for v in vulnerabilities if v["severity"] == "Severe"),
                        "exploitable_count": sum(1 for v in vulnerabilities if v.get("exploitable", False)),
                        "top_vulnerabilities": vulnerabilities[:25]  # Top 25 for the report
                    }
                    
                    logger.info(f"Processed {len(vulnerabilities)} Critical/Severe vulnerabilities")
                    logger.info(f"Found {len(all_cve_ids)} unique CVEs for correlation")
                    
                    return [summary]
                    
                elif response.status == 401:
                    logger.error("Rapid7 API authentication failed. Check API key.")
                    response_text = await response.text()
                    logger.error(f"Rapid7 response: {response_text[:500]}")
                    return []
                    
                elif response.status == 403:
                    logger.error("Rapid7 API access forbidden. Verify API key permissions.")
                    response_text = await response.text()
                    logger.error(f"Rapid7 response: {response_text[:500]}")
                    return []
                    
                elif response.status == 400:
                    logger.error("Rapid7 API bad request. Check request body format.")
                    response_text = await response.text()
                    logger.error(f"Rapid7 response: {response_text[:500]}")
                    return []
                    
                else:
                    logger.error(f"Rapid7 API returned status {response.status}")
                    response_text = await response.text()
                    logger.error(f"Rapid7 response: {response_text[:500]}")
                    return []
                    
    except aiohttp.ClientError as e:
        logger.error(f"Network error connecting to Rapid7 API: {e}", exc_info=True)
        return []
    except Exception as e:
        logger.error(f"Error fetching Rapid7 data: {e}", exc_info=True)
        return []