# Fortidiff v3.13

A semantic code comparison tool for Fortify FVDL/XML files that determines whether vulnerabilities have already been reviewed by analyzing code similarity and tracking vulnerability metadata across security scans.

## Purpose

Fortidiff helps security teams efficiently triage Fortify scan results by:
- Comparing code snippets between old and new security audits
- Identifying which vulnerabilities have already been reviewed based on code similarity
- Tracking vulnerability metadata (RuleID, Category, Priority, etc.) across scans
- Generating interactive HTML reports for easy review

## Installation

### Prerequisites
- Python 3.7 or higher ( I have a 2.7 version )
- Standard library only (no external dependencies required)

### Setup
```bash
# Make executable (optional, Linux/Mac)
chmod +x fortidiff.py

```

## Usage

### Basic Command
```bash
python fortidiff.py <old_fvdl> <new_fvdl>
```

### Command Line Arguments
```bash
python fortidiff.py old_scan.fvdl new_scan.fvdl [OPTIONS]

Required Arguments:
  old_fvdl              Path to the older FVDL export file
  new_fvdl              Path to the newer FVDL export file

Optional Arguments:
  --threshold INT       Similarity percentage threshold for marking as "Reviewed"
                       (default: 80)
  --out PATH           Output path for HTML report
                       (default: ./diff_code/snippet-diff.html)
```

### Examples

**Basic comparison with default threshold (80%):**
```bash
python fortidiff.py baseline_audit.fvdl latest_audit.fvdl
```

**Custom similarity threshold (90%):**
```bash
python fortidiff.py old.fvdl new.fvdl --threshold 90
```

**Custom output location:**
```bash
python fortidiff.py old.fvdl new.fvdl --out reports/security_diff.html
```


## Output Files

Fortidiff generates two output files:

1. **HTML Report** (`snippet-diff.html` by default)
   - Interactive web-based report
   - Expandable rows showing vulnerability details
   - Side-by-side code comparison
   - Color-coded similarity scores
   - Searchable and filterable

2. **JSON Summary** (same name as HTML with `.json` extension)
   - Machine-readable data
   - Complete vulnerability metadata
   - Similarity scores and status
   - Suitable for automation/integration

## Understanding the Results

### Similarity Scores
- **80-100%**: High similarity (typically "Already Reviewed")
- **50-79%**: Medium similarity (may need review)
- **0-49%**: Low similarity (requires review)

### Status Categories
- **Reviewed**: Code similarity ≥ threshold (already audited)
- **Needs Review**: Code similarity < threshold (requires attention)
- **Not found**: Code exists in old scan but not in new scan (removed/refactored)

### HTML Report Features
- Click any row to expand and view:
  - Full vulnerability metadata comparison (old vs new)
  - Complete Abstract/Description text
  - Side-by-side code snippets
  - File paths and line numbers
  - Rule IDs, Categories, and Priority levels

---

## High-Level Function Overview

### Core Workflow Functions

**`main()`**
- Entry point for the application
- Parses command line arguments
- Orchestrates the entire comparison workflow
- Generates output files and summary statistics

**`parse_all_vulnerabilities(fvdl_path)`**
- Extracts vulnerability metadata from FVDL files
- Returns a dictionary mapping snippet hashes to vulnerability details
- Handles namespace detection automatically

**`load_snippets(path)`**
- Detects FVDL format (snippet-based or vulnerability-based)
- Routes to appropriate extraction function
- Returns dictionary of code snippets with metadata

### Snippet Extraction Functions

**`extract_snippets_from_snippet_elements(xml_path)`**
- Extracts code snippets from `<Snippet>` XML elements
- Handles namespace variations in FVDL files
- Returns snippets with start line information

**`refine_snippets_from_snippet_elements(xml_path)`**
- Enhanced snippet extraction with improved error handling
- Extracts start line numbers for accurate code location tracking
- Processes both populated and empty snippet elements

**`extract_vulnerability_info(vuln, ns, use_ns)`**
- Extracts comprehensive metadata from a single vulnerability element
- Captures RuleID, Category, Kingdom, Priority, Abstract, file paths, etc.
- Parses snippet hash and location information

### Code Analysis Functions

**`normalize_code(code)`**
- Standardizes code format for comparison
- Removes comments, extra whitespace
- Normalizes strings and numbers to generic tokens
- Essential for semantic (meaning-based) comparison

**`tokenize(code)`**
- Breaks code into individual tokens (words, symbols, operators)
- Filters out empty strings while preserving meaningful elements
- Used for Jaccard similarity calculation

**`jaccard(a, b)`**
- Computes Jaccard similarity between two token sets
- Uses Counter objects to handle token frequency
- Returns similarity score (0.0 to 1.0)

**`similarity_score(old, new)`**
- Combines sequence matching and token-based similarity
- Weighted algorithm: 60% sequence matching + 40% Jaccard similarity
- Returns percentage score (0-100)

**`compare_sets(old_snips, new_snips, threshold)`**
- Performs pairwise comparison of all snippets
- Identifies matches, additions, and deletions
- Returns list of comparison results with status flags

### Report Generation Functions

**`build_html_report(old_raw, new_raw, old_vuln_map, new_vuln_map, compare_res, threshold)`**
- Generates interactive HTML report with expandable rows
- Creates side-by-side vulnerability metadata comparison
- Includes color-coded similarity scores and status badges
- Embeds JavaScript for row expansion functionality

### Utility Functions

**`_detect_format(root)`**
- Auto-detects FVDL format type (snippet-based vs vulnerability-based)
- Ensures correct parsing strategy is used

---

## Algorithm Details

### Similarity Calculation
The tool uses a hybrid approach combining:
1. **Sequence Matching**: Character-level comparison using Python's `SequenceMatcher`
2. **Token-Based Jaccard Similarity**: Vocabulary overlap analysis
3. **Weighted Combination**: `0.6 × sequence_ratio + 0.4 × jaccard_score`

This approach balances structural similarity with semantic meaning, making it robust against:
- Minor formatting changes
- Variable/function renaming
- Comment additions/removals
- Whitespace modifications

### Metadata Tracking
Fortidiff tracks 20+ vulnerability attributes including:
- Count, Instance ID, Rule ID
- Category, Kingdom, Friority (Priority)
- File names, paths, line numbers
- Abstract descriptions
- Snippet hashes and target functions

---

## Troubleshooting

### Common Issues

**"Unable to parse XML"**
- Ensure FVDL files are valid XML
- Check for corruption during export
- Verify files are complete (not truncated)

**"No results in OLD/NEW file"**
- FVDL file may be empty
- XML structure may not match expected format
- Try extracting FVDL from .fpr archive again

**Missing vulnerability metadata**
- Some fields may not exist in all FVDL versions
- Missing data is marked as "—" in reports
- Core comparison still functions with partial metadata

---

## Technical Notes

- **Namespace Handling**: Automatically detects and handles XML namespaces
- **Performance**: Processes hundreds of vulnerabilities in seconds
- **Memory**: Loads entire files into memory (suitable for typical FVDL sizes)
- **Encoding**: UTF-8 encoding for all output files

## Support 
Radoiz
