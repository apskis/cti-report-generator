# CTI Report Priority Rating System (P1/P2/P3)

## Overview

The CTI report uses a three-tier priority system (P1/P2/P3) to help security teams focus on the most critical vulnerabilities first. Priority is calculated by **fusing intelligence from multiple sources** to determine both the **likelihood** and **impact** of exploitation.

---

## Priority Definitions

### **P1 (Critical/Immediate Action Required)**
**Criteria:** Critical vulnerabilities that meet BOTH conditions:
- **In YOUR environment** (detected by Rapid7 or CrowdStrike Spotlight)
- **AND** actively being exploited (confirmed by Intel471 breach reports, CISA KEV, or CrowdStrike intelligence)

**Why P1?**
- The vulnerability exists in your infrastructure
- Attackers are actively using it in the wild
- You have a known attack surface
- Immediate risk of compromise

**Example:**
```
CVE-2026-1555 (WordPress vulnerability)
- Rapid7: Found on 3 production servers ✓
- Intel471: Used in breach of similar organization ✓
→ P1: Patch immediately
```

**Recommended Action:** Patch within 24-48 hours or implement emergency mitigations

---

### **P2 (High Priority)**
**Criteria:** Meets ONE of these conditions:
- **High/Critical severity AND active exploitation** (but not detected in your environment yet)
- **OR detected in your environment** (regardless of exploitation status)

**Why P2?**
- Either you're exposed OR it's being weaponized
- Significant risk but not both conditions met
- Requires prompt attention but not drop-everything urgent

**Examples:**

**Scenario A: Detected but not exploited**
```
CVE-2026-3461 (WordPress plugin)
- Rapid7: Found on 12 servers ✓
- Exploitation: None known ✗
→ P2: You're exposed, patch soon
```

**Scenario B: Exploited but not detected in your environment**
```
CVE-2026-39842 (OpenRemote)
- Rapid7: Not detected ✗
- CrowdStrike: APT groups exploiting it ✓
→ P2: Monitor and verify you're not affected
```

**Recommended Action:** Patch within 7-14 days or verify mitigation

---

### **P3 (Scheduled Action Required)**
**Criteria:**
- Important vulnerabilities requiring remediation
- Not detected in your environment
- No confirmed active exploitation
- OR lower severity (Medium) without exploitation

**Why P3?**
- Still requires patching/remediation, just lower urgency
- May affect you in future if systems change
- Proactive security posture
- May escalate to P1/P2 if exploitation begins or detected in environment

**Example:**
```
CVE-2026-5387 (UPS management software)
- Rapid7: Not detected ✗
- Exploitation: None known ✗
- Severity: High
→ P3: Schedule remediation within 30 days
```

**Recommended Action:** Schedule patching within 30 days, include in standard change window

---

## Priority Decision Tree

```
┌─────────────────────────────────────────────────┐
│  Is the CVE detected in your environment?       │
│  (Rapid7 or CrowdStrike Spotlight)             │
└─────────────────┬───────────────────────────────┘
                  │
        ┌─────────┴─────────┐
        │ YES               │ NO
        ▼                   ▼
┌───────────────────┐  ┌──────────────────────┐
│ Is it actively    │  │ Is it actively       │
│ exploited?        │  │ exploited?           │
│ (Intel471/CISA)   │  │ (Intel471/CISA)      │
└───────┬───────────┘  └──────┬───────────────┘
        │                      │
   ┌────┴────┐            ┌────┴────┐
   YES      NO            YES      NO
   │         │             │         │
   ▼         ▼             ▼         ▼
  P1        P2            P2        P3
```

---

## Real-World Examples

### P1 Scenario (Worst Case)
**CVE-2026-1555: WordPress WebStack theme RCE**
- **Severity:** CVSS 9.8 (Critical)
- **Your Environment:** 3 web servers (Rapid7)
- **Exploitation:** Ransomware groups (Intel471 breach report)
- **Priority:** P1 - IMMEDIATE ACTION
- **Action:** Patch 3 servers today, isolate if patch unavailable

---

### P2 Scenario A (You're Exposed)
**CVE-2026-3461: WordPress Visa plugin SQL injection**
- **Severity:** CVSS 9.8 (Critical)
- **Your Environment:** 12 servers (Rapid7)
- **Exploitation:** None known
- **Priority:** P2 - PATCH THIS WEEK
- **Action:** Schedule patches within 7 days

---

### P2 Scenario B (Active Exploitation)
**CVE-2026-39842: OpenRemote auth bypass**
- **Severity:** CVSS 9.1 (Critical)
- **Your Environment:** Not detected
- **Exploitation:** APT groups (CrowdStrike)
- **Priority:** P2 - VERIFY & MONITOR
- **Action:** Confirm you don't use OpenRemote, add to monitoring

---

### P3 Scenario (Awareness)
**CVE-2026-5617: WordPress Login as User plugin**
- **Severity:** CVSS 7.5 (High)
- **Your Environment:** Not detected
- **Exploitation:** None known
- **Priority:** P3 - SCHEDULED REMEDIATION
- **Action:** Schedule patch in next standard change window (within 30 days)

---

## Risk Calculation Formula

### **Risk = Likelihood × Impact**

| Priority | Likelihood | Impact | Risk Level |
|----------|------------|--------|------------|
| **P1** | High (in your environment + being exploited) | High | **CRITICAL RISK** |
| **P2** | Medium (exposed OR exploited) | High | **HIGH RISK** |
| **P3** | Low (not exposed, not exploited) | Variable | **MEDIUM RISK** |

---

## Intelligence Source Integration

The priority is calculated by **fusing multiple sources**:

```
Priority Calculation:
├─ NVD: Provides severity (CVSS score)
├─ Rapid7 InsightVM: Confirms "Is it in our environment?"
├─ CrowdStrike Falcon: Detects "Are we seeing exploitation attempts?"
├─ Intel471 Titan: Confirms "Is it used in real breaches?"
└─ CISA KEV: Government confirmation of active exploitation
```

### Source Weighting

| Source | What it tells us | Impact on Priority |
|--------|------------------|-------------------|
| **Rapid7** | Asset exposure | If present → minimum P2 |
| **Intel471** | Breach intelligence | If exploited in breaches → +1 priority level |
| **CrowdStrike** | APT/threat actor activity | If targeting sector → +1 priority level |
| **CISA KEV** | Government-confirmed exploitation | If listed → minimum P2 |

---

## Priority Matrix

| Scenario | In Environment? | Actively Exploited? | Priority | Timeline |
|----------|----------------|-------------------|----------|----------|
| Detected + Exploited | ✓ | ✓ | **P1** | 24-48 hours |
| Detected + Not Exploited | ✓ | ✗ | **P2** | 7-14 days |
| Not Detected + Exploited | ✗ | ✓ | **P2** | Verify + Monitor |
| Not Detected + Not Exploited | ✗ | ✗ | **P3** | 30 days |

---

## How AI Uses This Logic

The AI threat analyst agent receives:

1. **CVE list from NVD** (all published vulnerabilities)
2. **Rapid7 exposure map** (CVE ID → asset counts in your environment)
3. **CrowdStrike intelligence** (exploitation activity, threat actors)
4. **Intel471 breach reports** (CVEs used in actual breaches)

The AI then:
1. Checks if CVE is in Rapid7 exposure map
2. Checks if CVE is mentioned in Intel471 breaches or CISA KEV
3. Applies decision tree to assign P1/P2/P3
4. Generates "exploited_by" and "exposure" fields for report

---

## Priority Escalation/De-escalation

### **Escalate to P1 if:**
- P2 vulnerability is suddenly detected in environment
- P2 vulnerability appears in Intel471 breach reports
- CISA adds to KEV catalog

### **De-escalate from P1 to P2 if:**
- Vulnerability patched on all exposed systems
- Mitigation controls confirmed effective

### **De-escalate from P2 to P3 if:**
- Asset decommissioned (no longer in environment)
- Vendor releases patch and no active exploitation

---

## Customization Options

The priority system can be adjusted based on your needs:

### Option 1: Environmental Presence = Always P1
```
If (detected in environment) → P1
Regardless of exploitation status
```
**Use when:** You want aggressive patching of anything in your environment

### Option 2: CVSS-Based Auto-P1
```
If (CVSS >= 9.0 AND Critical/High) → P1
```
**Use when:** You trust CVSS scores and want severity-driven prioritization

### Option 3: Regulatory Compliance Factor
```
If (affects PCI/HIPAA/FDA systems) → +1 priority level
```
**Use when:** Compliance deadlines drive your patching schedule

### Option 4: Business Criticality
```
If (affects production/revenue systems) → +1 priority level
```
**Use when:** Business impact is primary concern

---

## Recommended SLA by Priority

| Priority | Patch Deadline | Exception Process |
|----------|---------------|-------------------|
| **P1** | 48 hours | CISO approval required for extension |
| **P2** | 14 days | Manager approval for extension |
| **P3** | 30 days | Standard change process |

---

## Questions to Consider

1. **Should P1 be "detected in environment" regardless of exploitation?**
   - Pro: More aggressive protection of your assets
   - Con: May overwhelm team with too many P1s

2. **Should certain CVSS scores (like 9.0+) automatically be P1?**
   - Pro: Simple, severity-based rule
   - Con: Doesn't consider environmental context

3. **Should regulatory/compliance factors influence priority?**
   - Pro: Aligns with audit requirements
   - Con: May not reflect actual risk

4. **Should business criticality affect priority?**
   - Pro: Protects revenue-generating systems first
   - Con: Requires maintaining asset criticality database

---

## System Configuration

Current priority logic is defined in:
- **File:** `src/agents/threat_analyst.py`
- **Function:** `_build_analysis_prompt()`
- **AI Prompt Section:** "Priority Guidelines"

To modify the logic, update the prompt instructions in the "Priority Guidelines" section.

---

## Reporting

The weekly CTI report shows:
- **P1 count** in "This Week at a Glance" metrics
- **Priority column** in "Vulnerability Exposure" table (color-coded)
- **Recommendations** section prioritized by P1 → P2 → P3

Color coding:
- 🔴 **P1/Critical**: Red tint background
- 🟡 **P2/Medium**: Yellow tint background  
- 🟢 **P3/Low**: Green tint background
