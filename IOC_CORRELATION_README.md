# IOC Correlation System

## Overview

The IOC Correlation system enriches raw threat indicators with threat actor attribution by joining data across multiple intelligence sources. It transforms isolated IOCs into actionable intelligence by linking them to known adversaries, campaigns, and TTPs.

## Architecture

```
┌─────────────────────┐
│   Data Collection   │
│  (Existing Pipeline)│
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐     ┌─────────────────────┐
│  ThreatQ Collector  │     │ CrowdStrike Collector│
│  - Indicators       │     │  - Actors            │
│  - Adversaries      │     │  - Indicators        │
└──────────┬──────────┘     └──────────┬──────────┘
           │                           │
           └───────────┬───────────────┘
                       ▼
              ┌─────────────────┐
              │  IOCCorrelator  │
              │                 │
              │ - Build indices │
              │ - Match IOCs    │
              │ - Enrich data   │
              │ - Score relevance│
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  EnrichedIOC    │
              │  Objects        │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Weekly Report  │
              │  (Tactical)     │
              └─────────────────┘
```

## Core Components

### IOCCorrelator Class

Location: `ioc_correlator.py`

The main correlation engine that joins IOC data across sources.

```python
from ioc_correlator import IOCCorrelator, CorrelationResult

correlator = IOCCorrelator(
    target_industries=["Healthcare", "Biotechnology", "Pharmaceutical"]
)

result = correlator.correlate(
    threatq_indicators=threatq_indicators,
    threatq_adversaries=threatq_adversaries,
    crowdstrike_actors=crowdstrike_actors,
    crowdstrike_indicators=crowdstrike_indicators
)
```

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target_industries` | `List[str]` | Healthcare, Pharma, Biotech, etc. | Industries to prioritize for relevance scoring |

#### Methods

**`correlate()`**

Main correlation method. Joins data from all sources and returns enriched IOCs.

```python
def correlate(
    self,
    threatq_indicators: List[Dict[str, Any]],
    threatq_adversaries: List[Dict[str, Any]],
    crowdstrike_actors: List[Dict[str, Any]],
    crowdstrike_indicators: List[Dict[str, Any]]
) -> CorrelationResult
```

**`get_high_priority_iocs()`**

Filter enriched IOCs by relevance score.

```python
def get_high_priority_iocs(
    self,
    result: CorrelationResult,
    min_relevance: int = 50,
    max_count: int = 20
) -> List[EnrichedIOC]
```

**`get_actor_summary()`**

Generate actor profiles with their associated IOCs.

```python
def get_actor_summary(self, result: CorrelationResult) -> List[Dict[str, Any]]
```

### EnrichedIOC Dataclass

Represents an IOC enriched with threat actor attribution.

```python
@dataclass
class EnrichedIOC:
    # Core IOC fields
    value: str                      # The actual indicator value
    indicator_type: str             # FQDN, IP, MD5, SHA256, URL, Email
    score: int                      # Severity score (0-10)
    status: str                     # Active, Review, Expired
    sources: List[str]              # Data sources (ThreatQ, CrowdStrike)
    
    # Attribution fields
    attributed_actors: List[str]    # Threat actor names
    actor_countries: List[str]      # Origin countries
    actor_motivations: List[str]    # Espionage, Financial, Hacktivism
    target_industries: List[str]    # Industries the actor targets
    ttps: List[str]                 # MITRE ATT&CK techniques
    
    # Context
    first_seen: str                 # ISO timestamp
    last_seen: str                  # ISO timestamp
    confidence: str                 # High, Medium, Low
    correlation_sources: List[str]  # How attribution was determined
    
    # Relevance
    relevance_score: int            # 0-100 based on org targeting
    relevance_reason: str           # Human readable explanation
```

### CorrelationResult Dataclass

Container for correlation output and statistics.

```python
@dataclass
class CorrelationResult:
    enriched_iocs: List[EnrichedIOC]
    attributed_count: int
    unattributed_count: int
    actors_identified: List[str]
    correlation_stats: Dict[str, int]
```

## Correlation Methods

The correlator uses three methods to establish attribution:

### 1. ThreatQ Native Linkage

ThreatQ stores explicit adversary-to-indicator relationships. When fetching adversaries with `?with=indicators`, the API returns linked indicator IDs.

```python
# ThreatQ adversary response includes indicator_ids
{
    "id": 100,
    "name": "APT Healthcare",
    "indicator_ids": [12345, 12346, 12347]
}
```

The correlator builds an index: `indicator_id → adversary` and uses it to attribute ThreatQ IOCs.

### 2. CrowdStrike IOC Cross Reference

CrowdStrike indicators include an `actors` field with attribution. The correlator:

1. Indexes all CrowdStrike IOCs by value (lowercase)
2. For each ThreatQ IOC, checks if the value exists in CrowdStrike
3. If matched, inherits the actor attribution

```python
# CrowdStrike indicator with attribution
{
    "indicator": "malicious.example.com",
    "actors": ["FANCY BEAR"],
    "malicious_confidence": "high"
}
```

### 3. Actor Profile Enrichment

When an IOC is attributed to an actor, the correlator pulls the full actor profile from CrowdStrike to add:

- Origin country
- Motivations (Espionage, Financial, etc.)
- Target industries
- TTPs (kill chain phases)

## Relevance Scoring

Each IOC receives a relevance score (0-100) based on:

| Factor | Points | Condition |
|--------|--------|-----------|
| Attribution | +30 | Has at least one attributed actor |
| Industry Targeting | +40 | Actor targets healthcare/biotech/pharma |
| IOC Score | +20 | Score >= 9 (Critical) |
| IOC Score | +15 | Score >= 7 (High) |
| IOC Score | +10 | Score >= 5 (Medium) |
| Confidence | +10 | High confidence attribution |
| Confidence | +5 | Medium confidence attribution |

Example: An IOC attributed to FANCY BEAR (targeting Healthcare) with score 9 and high confidence = 30 + 40 + 20 + 10 = 100

## Integration

### With Existing Pipeline

```python
from collectors import collect_all, get_data_by_source
from threatq_collector import separate_threatq_data
from ioc_correlator import IOCCorrelator

async def collect_and_correlate(credentials):
    # Collect from all sources
    collector_results = await collect_all(credentials)
    data_by_source = get_data_by_source(collector_results)
    
    # Separate data types
    threatq_data = data_by_source.get("ThreatQ", [])
    crowdstrike_data = data_by_source.get("CrowdStrike", [])
    
    threatq_indicators, threatq_adversaries = separate_threatq_data(threatq_data)
    crowdstrike_actors, crowdstrike_indicators = separate_crowdstrike_data(crowdstrike_data)
    
    # Correlate
    correlator = IOCCorrelator()
    result = correlator.correlate(
        threatq_indicators=threatq_indicators,
        threatq_adversaries=threatq_adversaries,
        crowdstrike_actors=crowdstrike_actors,
        crowdstrike_indicators=crowdstrike_indicators
    )
    
    return result
```

### With AI Analysis

Pass correlated data to the ThreatAnalystAgent:

```python
analysis_input = {
    "correlated_iocs": [ioc.to_dict() for ioc in high_priority_iocs],
    "relevant_actors": actor_summary,
    "statistics": result.correlation_stats
}

analysis = await agent.analyze_threats_with_correlation(**analysis_input)
```

## ThreatQ Collector Updates

The ThreatQ collector now fetches both indicators and adversaries:

```python
# collectors/threatq_collector.py

async def collect(self) -> CollectorResult:
    # Fetches indicators with score >= threshold
    indicators = await self._fetch_indicators(client, url, token)
    
    # Fetches adversaries with linked indicator IDs
    adversaries = await self._fetch_adversaries(client, url, token)
    
    # Returns combined data with data_type markers
    return CollectorResult(data=indicators + adversaries)
```

Use `separate_threatq_data()` utility to split them:

```python
from threatq_collector import separate_threatq_data

indicators, adversaries = separate_threatq_data(threatq_collector_result.data)
```

## Configuration

### Collector Config (config.py)

```python
@dataclass(frozen=True)
class CollectorConfig:
    threatq_lookback_days: int = 7
    threatq_indicators_limit: int = 100
    threatq_min_score: int = 7  # Minimum score threshold
```

### Azure Key Vault Secrets

| Secret Name | Description |
|-------------|-------------|
| `threatq-url` | ThreatQ instance URL |
| `threatq-client-id` | OAuth2 client ID |
| `threatq-client-secret` | OAuth2 client secret |

## Output Examples

### Enriched IOC

```python
EnrichedIOC(
    value="malicious.biotech-target.com",
    indicator_type="FQDN",
    score=9,
    status="Active",
    sources=["ThreatQ", "Internal Analysis"],
    attributed_actors=["APT Healthcare", "FANCY BEAR"],
    actor_countries=["China", "Russia"],
    actor_motivations=["Espionage", "IP Theft"],
    target_industries=["Healthcare", "Biotechnology", "Pharmaceutical"],
    ttps=["Spearphishing", "Credential Harvesting", "Data Exfiltration"],
    confidence="High",
    correlation_sources=["ThreatQ Adversary", "CrowdStrike"],
    relevance_score=95,
    relevance_reason="Attributed to APT Healthcare; Targets Biotechnology"
)
```

### Actor Summary

```python
{
    "actor_name": "APT Healthcare",
    "country": "China",
    "motivations": ["Espionage", "IP Theft"],
    "target_industries": ["Healthcare", "Biotechnology", "Pharmaceutical"],
    "ttps": ["Spearphishing", "Supply Chain", "Zero Day"],
    "ioc_count": 15,
    "sample_iocs": ["malicious.com", "192.168.1.100", "evil.biotech.cn"],
    "avg_score": 8.2,
    "relevant_to_org": True,
    "relevance_note": "Targets healthcare/biotech sector"
}
```

## Limitations

The IOCCorrelator performs deterministic data joining only:

| What It Does | What It Does NOT Do |
|--------------|---------------------|
| Exact value matching | Fuzzy/similar matching |
| Explicit relationship lookups | Inferred relationships |
| Fixed scoring formula | Contextual reasoning |
| Fast, consistent results | Pattern recognition |

For intelligent analysis, semantic understanding, and narrative generation, pass the correlated data to an AI agent (see `AI_AGENT_RECOMMENDATION.md`).

## Files

| File | Purpose |
|------|---------|
| `ioc_correlator.py` | Core correlation engine |
| `threatq_collector.py` | Updated collector with adversary fetching |
| `ioc_correlation_integration.py` | Pipeline integration examples |

## Dependencies

- Python 3.11+
- Existing collector infrastructure
- ThreatQ API access (OAuth2 client credentials)
- CrowdStrike API access (OAuth2 client credentials)
