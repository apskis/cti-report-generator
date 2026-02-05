# AI Agent Recommendation: Threat Intelligence Reasoning Layer

## Executive Summary

The IOCCorrelator provides deterministic data joining across threat intelligence sources. However, true threat intelligence requires reasoning, pattern recognition, and contextual analysis that only an AI agent can provide. This document recommends building a **ThreatCorrelationAgent** that operates on top of the correlated data to produce actionable intelligence assessments.

## The Gap: Data Joining vs. Intelligence Analysis

### What IOCCorrelator Does (Deterministic)

```
Input: Raw IOCs from ThreatQ + CrowdStrike
Process: Exact matching, lookup tables, fixed formulas
Output: Enriched IOCs with explicit attributions
```

| Capability | Example |
|------------|---------|
| Exact value matching | "malicious.com" exists in both sources |
| Explicit relationships | ThreatQ says indicator X belongs to adversary Y |
| Fixed scoring | Attribution (+30) + Industry targeting (+40) = 70 |

### What an AI Agent Could Do (Intelligent)

```
Input: Enriched IOCs + Context + Organization Profile
Process: Reasoning, inference, pattern recognition
Output: Intelligence assessment with recommendations
```

| Capability | Example |
|------------|---------|
| Fuzzy matching | "malicious-biotech.com" is likely related to "malicious-healthcare.com" |
| Inferred relationships | "This IP hosted malware used by APT X last month" |
| Contextual scoring | "Critical for Illumina because genomics IP theft is APT X's specialty" |
| Pattern recognition | "Three actors are converging on biotech supply chain attacks" |
| Narrative generation | "This week's activity suggests coordinated reconnaissance" |

## Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     CTI Report Pipeline                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Data Collection                            │
│  NVD │ Intel471 │ CrowdStrike │ ThreatQ │ Rapid7               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      IOCCorrelator                              │
│  (Deterministic data joining - fast, consistent)                │
│  Output: EnrichedIOC objects with explicit attributions         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  ThreatCorrelationAgent                         │
│  (AI reasoning layer - intelligent analysis)                    │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Relationship│  │  Relevance  │  │  Narrative  │             │
│  │  Inference  │  │  Assessment │  │  Generation │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                 │
│  Output: Intelligence assessment with recommendations           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Report Generation                           │
│  Weekly Tactical │ Quarterly Strategic                          │
└─────────────────────────────────────────────────────────────────┘
```

## ThreatCorrelationAgent Design

### Purpose

Transform enriched IOC data into intelligence assessments that answer:

1. **What's happening?** — Threat activity summary
2. **Who's behind it?** — Actor attribution and profiling  
3. **Why does it matter to us?** — Organizational relevance
4. **What should we do?** — Prioritized recommendations

### Agent Responsibilities

| Responsibility | Description |
|----------------|-------------|
| Relationship Inference | Identify connections the correlator missed (similar domains, shared infrastructure, campaign patterns) |
| Contextual Relevance | Assess threats against Illumina's specific profile (genomics, biotech IP, research data) |
| Priority Assessment | Determine which IOCs require immediate action vs. monitoring |
| Actor Profiling | Synthesize actor intelligence into actionable profiles |
| Trend Analysis | Identify patterns across time (increasing activity, new TTPs) |
| Recommendation Generation | Produce specific, actionable defensive measures |
| Narrative Synthesis | Write the executive summary and threat assessment sections |

### Input Schema

```python
@dataclass
class AgentInput:
    # From IOCCorrelator
    enriched_iocs: List[EnrichedIOC]
    actor_summary: List[Dict[str, Any]]
    correlation_stats: Dict[str, int]
    
    # From other collectors
    cve_data: List[Dict[str, Any]]
    intel471_reports: List[Dict[str, Any]]
    rapid7_vulnerabilities: List[Dict[str, Any]]
    
    # Organization context
    org_profile: OrganizationProfile
    
    # Historical context
    previous_week_summary: Optional[str]
    known_threats: List[str]

@dataclass
class OrganizationProfile:
    name: str = "Illumina"
    industry: str = "Genomics/Biotechnology"
    
    # What we care about
    critical_assets: List[str] = field(default_factory=lambda: [
        "Genomic sequencing data",
        "Research IP",
        "Clinical trial data",
        "Customer PII/PHI",
        "Manufacturing systems"
    ])
    
    # Who targets us
    threat_actors_of_concern: List[str] = field(default_factory=lambda: [
        "APT41",  # China - biotech IP theft
        "APT10",  # China - healthcare targeting
        "FIN7",   # Financial - ransomware
        "Lazarus" # DPRK - financial + espionage
    ])
    
    # Our technology stack (for CVE relevance)
    technology_stack: List[str] = field(default_factory=lambda: [
        "Azure",
        "Windows Server",
        "Linux",
        "Python",
        "Kubernetes"
    ])
    
    # Geographic presence
    regions: List[str] = field(default_factory=lambda: [
        "United States",
        "Europe",
        "Asia Pacific"
    ])
```

### Output Schema

```python
@dataclass
class AgentOutput:
    # Executive summary (2-3 paragraphs)
    executive_summary: str
    
    # Threat assessment
    threat_level: str  # Critical, High, Medium, Low
    threat_level_justification: str
    
    # Priority IOCs with reasoning
    priority_iocs: List[PriorityIOC]
    
    # Actor assessments
    actor_assessments: List[ActorAssessment]
    
    # Inferred relationships (what the correlator missed)
    inferred_relationships: List[InferredRelationship]
    
    # Recommendations
    immediate_actions: List[str]  # Do this now
    short_term_actions: List[str]  # This week
    monitoring_items: List[str]   # Watch for this
    
    # Statistics for report
    statistics: Dict[str, Any]

@dataclass
class PriorityIOC:
    ioc: EnrichedIOC
    priority: str  # P1, P2, P3
    reasoning: str
    recommended_action: str  # Block, Monitor, Investigate

@dataclass  
class ActorAssessment:
    actor_name: str
    threat_to_org: str  # Critical, High, Medium, Low
    reasoning: str
    recent_activity: str
    recommended_defenses: List[str]

@dataclass
class InferredRelationship:
    ioc_a: str
    ioc_b: str
    relationship_type: str  # "similar_domain", "shared_infrastructure", "same_campaign"
    confidence: str
    reasoning: str
```

### Agent Implementation Approach

#### Option A: Single Prompt Agent

Simple implementation using one comprehensive prompt.

```python
class ThreatCorrelationAgent:
    def __init__(self, openai_endpoint: str, openai_key: str, deployment_name: str):
        self.kernel = semantic_kernel.Kernel()
        # Setup Azure OpenAI connection
        
    async def analyze(self, input: AgentInput) -> AgentOutput:
        prompt = self._build_prompt(input)
        response = await self.kernel.invoke(prompt)
        return self._parse_response(response)
```

**Pros:** Simple, single API call, easy to debug
**Cons:** Limited reasoning depth, context window constraints

#### Option B: Multi-Step Agent (Recommended)

Chain of specialized analysis steps.

```python
class ThreatCorrelationAgent:
    async def analyze(self, input: AgentInput) -> AgentOutput:
        # Step 1: Relationship inference
        relationships = await self._infer_relationships(input.enriched_iocs)
        
        # Step 2: Actor assessment
        actor_assessments = await self._assess_actors(
            input.actor_summary, 
            input.org_profile
        )
        
        # Step 3: IOC prioritization
        priority_iocs = await self._prioritize_iocs(
            input.enriched_iocs,
            actor_assessments,
            input.org_profile
        )
        
        # Step 4: Recommendation generation
        recommendations = await self._generate_recommendations(
            priority_iocs,
            actor_assessments,
            input.cve_data
        )
        
        # Step 5: Narrative synthesis
        summary = await self._synthesize_narrative(
            priority_iocs,
            actor_assessments,
            recommendations
        )
        
        return AgentOutput(...)
```

**Pros:** Deeper reasoning, specialized prompts, better quality
**Cons:** More API calls, higher latency, more complex

#### Option C: Tool-Using Agent (Advanced)

Agent with access to tools for dynamic analysis.

```python
class ThreatCorrelationAgent:
    tools = [
        SearchVirusTotalTool(),      # Lookup IOC reputation
        QueryMITREAttackTool(),      # Get TTP details
        SearchHistoricalIOCsTool(),  # Check if we've seen this before
        CheckAssetExposureTool(),    # Is this IOC hitting our systems?
    ]
    
    async def analyze(self, input: AgentInput) -> AgentOutput:
        # Agent decides which tools to use based on the data
        ...
```

**Pros:** Dynamic analysis, can gather additional context
**Cons:** Most complex, unpredictable latency, requires tool infrastructure

### Recommended Prompts

#### Relationship Inference Prompt

```
You are analyzing threat indicators for a genomics/biotechnology company.

## Enriched IOCs
{enriched_iocs_json}

## Task
Identify relationships between IOCs that may not be explicitly linked:

1. **Domain Similarity**: Look for domains with similar patterns, registrars, or naming conventions
2. **Infrastructure Sharing**: IPs that may host multiple malicious domains
3. **Campaign Indicators**: IOCs that appear to be part of the same campaign
4. **Actor Overlap**: IOCs attributed to different actors that may actually be related

For each inferred relationship, provide:
- The two IOCs involved
- Relationship type
- Confidence level (High/Medium/Low)
- Reasoning

Output JSON format:
{
    "inferred_relationships": [
        {
            "ioc_a": "...",
            "ioc_b": "...",
            "relationship_type": "...",
            "confidence": "...",
            "reasoning": "..."
        }
    ]
}
```

#### Actor Assessment Prompt

```
You are assessing threat actors for Illumina, a genomics/biotechnology company.

## Organization Profile
- Industry: Genomics/Biotechnology
- Critical Assets: Genomic sequencing data, Research IP, Clinical trial data
- Regions: United States, Europe, Asia Pacific

## Actor Summary
{actor_summary_json}

## Task
For each actor, assess:

1. **Threat Level to Illumina** (Critical/High/Medium/Low)
   - Do they specifically target biotech/healthcare?
   - What is their motivation (espionage, financial, destruction)?
   - Have they targeted similar companies?

2. **Reasoning**: Why this threat level?

3. **Recent Activity**: What does their IOC activity suggest?

4. **Recommended Defenses**: Specific countermeasures for this actor's TTPs

Output JSON format:
{
    "actor_assessments": [
        {
            "actor_name": "...",
            "threat_to_org": "...",
            "reasoning": "...",
            "recent_activity": "...",
            "recommended_defenses": ["...", "..."]
        }
    ]
}
```

#### IOC Prioritization Prompt

```
You are prioritizing threat indicators for immediate action.

## Organization Context
- Industry: Genomics/Biotechnology  
- Critical Assets: {critical_assets}
- Technology Stack: {technology_stack}

## Enriched IOCs
{enriched_iocs_json}

## Actor Assessments
{actor_assessments_json}

## Task
Assign each IOC a priority (P1/P2/P3) based on:

**P1 (Immediate Action Required)**
- Attributed to actor with Critical/High threat to org
- High relevance score (>=80)
- Active exploitation or recent activity
- Targets our specific technology stack

**P2 (Action Within 24-48 Hours)**
- Attributed to known threat actor
- Medium-High relevance (50-79)
- General biotech/healthcare targeting

**P3 (Monitor)**
- Unattributed or low-relevance actors
- Lower scores
- No clear targeting of our sector

For each IOC, provide:
- Priority level
- Reasoning
- Recommended action (Block, Investigate, Monitor)

Output JSON format:
{
    "priority_iocs": [
        {
            "value": "...",
            "priority": "P1",
            "reasoning": "...",
            "recommended_action": "Block"
        }
    ]
}
```

#### Narrative Synthesis Prompt

```
You are writing the threat intelligence summary for Illumina's weekly CTI report.

## This Week's Data
- Total IOCs analyzed: {total_iocs}
- IOCs with attribution: {attributed_count}
- High priority IOCs: {p1_count}
- Threat actors identified: {actor_count}
- Actors targeting our sector: {relevant_actor_count}

## Priority IOCs
{priority_iocs_json}

## Actor Assessments  
{actor_assessments_json}

## Inferred Relationships
{relationships_json}

## Task
Write a 2-3 paragraph executive summary that:

1. **Opens with the threat level** and most significant finding
2. **Highlights actor activity** relevant to genomics/biotech
3. **Notes patterns or trends** (e.g., "increased reconnaissance", "new TTPs observed")
4. **Closes with key recommendation**

Tone: Professional, direct, actionable. Avoid jargon. Write for a security-aware but non-technical executive audience.

Do NOT use bullet points in the summary. Write in prose paragraphs.
```

## Implementation Roadmap

### Phase 1: Single Prompt Agent (Week 1-2)

1. Create `ThreatCorrelationAgent` class
2. Implement single comprehensive prompt
3. Integrate with existing `ThreatAnalystAgent` or replace it
4. Test with sample correlated data
5. Validate output quality

### Phase 2: Multi-Step Agent (Week 3-4)

1. Split into specialized analysis steps
2. Implement relationship inference
3. Implement actor assessment
4. Implement IOC prioritization
5. Implement narrative synthesis
6. Chain steps together

### Phase 3: Historical Context (Week 5-6)

1. Store weekly analysis results
2. Pass previous week's summary to agent
3. Enable trend detection ("activity increased 40% vs last week")
4. Track actor activity over time

### Phase 4: Tool Integration (Future)

1. Add VirusTotal lookup for IOC enrichment
2. Add MITRE ATT&CK lookup for TTP context
3. Add historical IOC search (have we seen this before?)
4. Add asset exposure check (is this IOC in our logs?)

## Success Metrics

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Attribution rate | >80% of high-score IOCs | Count attributed vs total |
| Relevance accuracy | >90% P1s are truly critical | Manual review sample |
| Time to insight | <5 min for weekly analysis | Pipeline timing |
| Actionability | 100% of P1s have clear action | Review recommendations |
| False positive rate | <10% of blocked IOCs | Track blocks that get unblocked |

## Integration with Weekly Report

The agent output maps to report sections:

| Agent Output | Report Section |
|--------------|----------------|
| `executive_summary` | Executive Summary |
| `priority_iocs` | Attributed Threat Activity table |
| `actor_assessments` | APT Activity section |
| `immediate_actions` | Recommendations section |
| `statistics` | Threat Landscape Overview |

## Conclusion

The IOCCorrelator provides the data foundation. The ThreatCorrelationAgent provides the intelligence layer. Together, they transform raw IOCs into actionable threat intelligence that answers "what should Illumina do about this?"

Recommended next step: Implement Phase 1 (Single Prompt Agent) and validate output quality before investing in the more complex multi-step approach.
