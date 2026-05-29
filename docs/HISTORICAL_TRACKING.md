# Quarterly Risk Assessment Historical Tracking

## Overview

The quarterly report generator now includes **historical tracking** for risk assessments. This enables true quarter-over-quarter comparison instead of AI-assessed trends.

## How It Works

### Automatic Storage

Each time a quarterly report is generated, the system automatically:

1. **Saves** the current quarter's risk assessment to `data/historical/quarterly_risk_history.json`
2. **Loads** the previous quarter's risk assessment (if available)
3. **Compares** the two quarters to calculate real trend indicators

### Historical Data Format

```json
{
  "2026-Q2": {
    "timestamp": "2026-05-28T20:46:40.083516",
    "year": 2026,
    "quarter": 2,
    "nation_state": "MEDIUM",
    "ransomware": "HIGH",
    "supply_chain": "LOW",
    "insider": "LOW"
  },
  "2026-Q3": {
    "timestamp": "2026-08-15T00:00:00",
    "year": 2026,
    "quarter": 3,
    "nation_state": "HIGH",
    "ransomware": "HIGH",
    "supply_chain": "MEDIUM",
    "insider": "LOW"
  }
}
```

### Trend Calculation

The system compares risk levels numerically:
- **LOW** = 1
- **MEDIUM** = 2  
- **HIGH** = 3

Trend indicators:
- **↑** (Increased) - Current level > Previous level
- **↓** (Decreased) - Current level < Previous level
- **Unchanged** - Current level = Previous level

### Example

**Q2 2026 Risk Levels:**
- Nation-State: MEDIUM
- Supply Chain: LOW

**Q3 2026 Risk Levels:**
- Nation-State: HIGH (↑ Increased from Q2)
- Supply Chain: MEDIUM (↑ Increased from Q2)

## First Quarter Behavior

When generating a report for a quarter with no historical data (e.g., the first quarterly report ever generated), all trends will show as "Unchanged" since there's no previous quarter to compare against.

## Data Location

- **File:** `data/historical/quarterly_risk_history.json`
- **Format:** JSON
- **Backup:** Recommended to include this file in version control or regular backups

## Benefits

1. **Accurate Trends** - Real quarter-over-quarter comparison instead of AI guesses
2. **Historical Context** - Track risk assessment evolution over time
3. **Audit Trail** - Timestamped history of all quarterly assessments
4. **Simple Implementation** - Flat file storage, no database required

## Technical Details

### New Methods in `QuarterlyReportGenerator`

- `_get_historical_file_path()` - Returns path to history file
- `_load_historical_data()` - Loads history from JSON
- `_save_historical_data()` - Saves history to JSON
- `_get_quarter_key()` - Generates quarter identifier (e.g., "2026-Q3")
- `_calculate_previous_quarter()` - Calculates previous quarter's year/number
- `_save_current_risk_assessment()` - Stores current quarter's assessment
- `_compare_with_previous_quarter()` - Calculates trend indicator

### Modified Methods

- `_add_risk_assessment()` - Now loads historical data and calculates real trends before rendering risk cards
