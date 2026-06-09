---
name: supply-chain-audit
description: "Perform a supply chain vulnerability analysis across ADT ecosystem repos. Verifies commit signing, PR traceability, CI integrity, and dependency provenance within a time frame. Generates a standalone HTML dashboard report."
version: "1.1"
allowed-tools: Read, Grep, Glob, Shell, WebSearch, WebFetch, Write, AskUserQuestion
argument-hint: "help | [last N days] | [YYYY-MM-DD YYYY-MM-DD] | [dive SCA-NNN]"
mandatory: false
type: workflow
triggers:
  - "supply chain audit"
  - "supply chain"
  - "commit integrity"
  - "dependency provenance"
  - "supply-chain-audit help"
  - "supply-chain-audit dive"
---

# Supply Chain Audit

Perform a two-phase supply chain vulnerability analysis across the Ansible DevTools ecosystem repositories.

## Target Repositories

All under `github.com/ansible/`:

1. ansible-builder
2. ansible-compat
3. ansible-creator
4. ansible-dev-environment
5. ansible-lint
6. ansible-navigator
7. ansible-sign
8. molecule
9. pytest-ansible
10. tox-ansible
11. ansible-dev-tools
12. vscode-ansible

## Input

The user provides arguments as: `$ARGUMENTS`

### Mode: Help

```
help
```

If `$ARGUMENTS` is `help`, print the **Help Content** section below and stop. Do not run any scripts.

### Mode: Dive (Finding Investigation)

```
dive SCA-NNN
```

If `$ARGUMENTS` starts with `dive`, extract the finding ID (e.g., `SCA-023`). Then:

1. Find the most recent cache directory under `.supply-chain-audit/cache/`
2. Read `findings.json` and locate the finding with matching `"id"` field
3. Present the full finding details to the user: repo, category, risk level, summary, evidence, commit SHA, PR number (with links)
4. Read the relevant section from `.agents/skills/supply-chain-audit/references/detection-patterns.md` for that finding's category
5. Provide the investigation steps from the detection pattern reference
6. Offer to investigate further (e.g., fetch the commit diff, check the PR timeline, look up the advisory)

Stop after presenting the deep-dive. Do not run analysis or generate reports.

### Phase 1 (Full Audit)

```
<start-date> <end-date>
```

Or a natural-language relative range:

```
last 7 days
last 30 days
last 2 weeks
```

If the user provides a relative range like "last 7 days" or "last 2 weeks", compute the actual ISO dates yourself:
- `end_date` = today (YYYY-MM-DD)
- `start_date` = today minus the specified duration

Example: `2025-01-01 2025-03-01` or `last 7 days`

### Phase 2 (Package Focus)

```
<start-date> <end-date> <package-name> <compromise-date>
```

Example: `2025-01-01 2025-03-01 requests 2025-02-15`

The compromise-date is the date the package is suspected to have been compromised.

## Prerequisites

- `gh` CLI installed and authenticated (`gh auth status` must succeed)
- `python3` available (3.10+)
- Network access to GitHub API and PyPI/npm registries

## Instructions

### Step 1: Validate inputs

Parse `$ARGUMENTS` to extract:
- `start_date` and `end_date` (required, ISO format YYYY-MM-DD)
- Optionally: `package_name` and `compromise_date` (for Phase 2)

If the user provides a relative range (e.g., "last 7 days", "last 2 weeks", "last 30 days"), resolve it to concrete dates:
- `end_date` = today's date
- `start_date` = today minus the specified duration

If arguments are missing or malformed, ask the user to provide them in the correct format and stop.

Verify prerequisites:
```bash
gh auth status
python3 --version
```

If either fails, inform the user and stop.

### Step 2: Run data collection

Execute the collection script from the skill's scripts directory:

```bash
python3 .agents/skills/supply-chain-audit/scripts/collect.py \
  --start "$start_date" \
  --end "$end_date" \
  --cache-dir ".supply-chain-audit/cache"
```

This will:
- Create the cache directory structure
- Fetch commits, PRs, check suites, and dependency diffs for all 12 repos
- Fetch all individual commits and review timelines within each merged PR
- Fetch branch protection rules and rulesets for each repo
- Store results as JSON in the cache directory
- Write a `manifest.json` for reproducibility

The script is idempotent: if cache files already exist for the same time frame, they are reused without re-fetching.

Monitor progress output. The script prints per-repo status. If rate-limited, it will back off automatically.

### Step 3: Run anomaly analysis

```bash
python3 .agents/skills/supply-chain-audit/scripts/analyze.py \
  --cache-dir ".supply-chain-audit/cache"
```

This detects (14 passes):
- Unsigned commits
- GitHub-web-signed commits (signer is GitHub, not a personal key)
- Orphan commits (no associated PR)
- Bypassed CI (merged with failing required checks)
- Post-merge pushes (commits after PR closed/merged)
- Replicated commit messages (near-duplicate of earlier commit)
- Renovate cooldown violations (dep adopted before configured `minimumReleaseAge`)
- Yanked/deleted package versions
- Branch protection rule changes or weak protection posture
- Post-approval commits in PRs (code pushed after review approval)
- Bot-only approvals (PRs merged without any human review)
- Self-approved PRs (author approved their own code with no independent review)
- Known vulnerabilities (all current packages scanned against OSV.dev)
- Suspicious file patterns (`.claude/`, `.vscode/tasks.json`, CI/CD config changes)

Output: `findings.json` in the cache directory.

### Step 4: (Optional) Run package focus analysis

If the user provided a package name and compromise date:

```bash
python3 .agents/skills/supply-chain-audit/scripts/check_package.py \
  --cache-dir ".supply-chain-audit/cache" \
  --package "$package_name" \
  --compromise-date "$compromise_date"
```

Output: `package_focus.json` in the cache directory.

### Step 5: Write security recommendations

After analysis completes, **you** (the agent) must read the findings and write a prioritized top-10 list of actionable security recommendations specific to what was found.

1. Read the findings summary: `.supply-chain-audit/cache/<hash>/findings_summary.json` (compact aggregate view — categories, risk counts, per-repo breakdown, top findings per category)
2. If you need more detail on specific findings, read the full: `.supply-chain-audit/cache/<hash>/findings.json`
3. Read the protection rules: `.supply-chain-audit/cache/<hash>/protection/*.json`
4. Read the renovate configs: `.supply-chain-audit/cache/<hash>/renovate/*.json`
5. Reason about the most impactful actions the team should take based on:
   - Severity and count of findings by category
   - Patterns across repos (e.g., many repos missing the same protection)
   - Quick wins vs. systemic improvements
   - What would prevent the *worst* findings from recurring
5. Write `.supply-chain-audit/cache/<hash>/recommendations.json` as a JSON array of objects:

```json
[
  {
    "title": "Short actionable title",
    "detail": "HTML-safe explanation with context, affected repos, and concrete steps."
  }
]
```

Guidelines for writing recommendations:
- Be specific to what was actually found (reference repo names, counts, categories)
- Order by impact: what would eliminate the most critical/high findings first
- Don't be generic — tailor every recommendation to this audit's actual data
- Link findings to their root cause (e.g., "bot-only approvals exist because branch protection doesn't require human review")
- Recommendations should span THREE categories:
  1. **Technical controls** — GitHub settings, branch protection rules, CI config changes
  2. **Process/behavioral changes** — team policies, review norms, merge hygiene (e.g., "adopt a policy that bot-only approvals are never sufficient for human-authored code", "require a second human reviewer for changes to CI or dependency files")
  3. **Operational practices** — audit cadence, monitoring, incident response readiness
- Don't just tell them what to configure — tell them what habits to adopt and what behaviors to stop tolerating
- Concrete examples: "Stop merging PRs with only bot approval", "Rotate a security champion weekly to review this report", "Treat post-approval commits as a blocking concern in code review culture"

### Step 6: Generate HTML report

```bash
python3 .agents/skills/supply-chain-audit/scripts/report.py \
  --cache-dir ".supply-chain-audit/cache" \
  --output ".supply-chain-audit/report.html"
```

This produces a standalone HTML file (no CDN dependencies) with:
- Executive summary (traffic-light per repo)
- Timeline visualization (SVG)
- Commit integrity table (sortable, filterable)
- Dependency changes table with release dates
- Suspicious patterns grouped by category
- Security recommendations (from step 5)
- Package focus section (if Phase 2 data exists)

### Step 7: Present results

After the report is generated:

1. Print a summary of findings:
   - Total commits analyzed
   - Number of anomalies found per category
   - Repos with highest risk indicators
2. Provide the path to the HTML report file
3. Highlight the top 3 recommendations with brief rationale
4. If Phase 2 was run, summarize which repos pulled in the suspect package and when

If critical findings are detected (bypassed CI, post-merge pushes, suspicious dep timing), highlight these prominently and recommend immediate investigation.

## Cache Behavior

- Cache location: `.supply-chain-audit/cache/`
- Cache key: first 16 hex chars of SHA-256(`start_date + end_date + sorted_repo_list`)
- Re-running with identical parameters produces identical output
- To force a fresh collection, delete the cache directory or pass `--force` to collect.py
- Git history is effectively immutable for merged PRs; cached data reflects the state at collection time

---

## Help Content

Print this section verbatim when the user invokes `/supply-chain-audit help`.

### What This Skill Does

Performs a comprehensive supply chain integrity analysis across 12 Ansible DevTools repositories. It collects commit, PR, CI, dependency, and branch protection data via the GitHub API, then runs 13 anomaly detection passes to identify integrity risks. Results are presented as a standalone HTML dashboard with numbered findings (SCA-001, SCA-002, ...) that can be individually investigated.

### Detection Categories

| # | Category | Risk | What It Detects |
|---|----------|------|-----------------|
| 1 | Unsigned Commits | Medium | Commits without GPG/SSH signatures — cannot be cryptographically attributed |
| 2 | GitHub-Web-Signed | Low | Commits signed by GitHub's key (not personal) — web UI edits, merge button |
| 3 | Orphan Commits | High | Commits on default branch with no associated PR — bypassed code review |
| 4 | Bypassed CI | High | PRs merged with failing *required* status checks |
| 5 | Post-Merge Pushes | Critical | Commits pushed to a branch *after* its PR was merged — known attack vector |
| 6 | Replicated Messages | High | Near-duplicate commit messages from different authors — impersonation indicator |
| 7 | Suspicious Dep Timing | High | Dependencies adopted within days of release — possible poisoned package |
| 8 | Yanked Versions | Critical | Dependencies referencing versions removed from registries |
| 9 | Branch Protection Changes | Medium | Modifications to branch protection rules within the audit window |
| 10 | Post-Approval Commits | High | Code pushed to a PR *after* reviewer approval — sneaking in changes |
| 11 | Bot-Only Approval | Medium | PRs merged with only bot approvals, no human review |
| 12 | Renovate Cooldown Violated | Critical | Deps adopted before the configured `minimumReleaseAge` elapsed |
| 13 | Known Vulnerabilities | Critical/High | Packages with disclosed CVEs/GHSAs per OSV.dev |
| 14 | Suspicious File Patterns | Critical/High | `.claude/` dirs (malware), CI/CD config changes, `.vscode/tasks.json` |

### How to Invoke

| Mode | Syntax | Purpose |
|------|--------|---------|
| Full audit (dates) | `/supply-chain-audit 2025-05-29 2025-06-05` | Run all 13 checks for the date range |
| Full audit (relative) | `/supply-chain-audit last 7 days` | Same as above, using today minus 7 days |
| Package focus | `/supply-chain-audit 2025-05-29 2025-06-05 jinja2 2025-06-01` | Full audit + deep-dive on a specific package compromise |
| Investigate finding | `/supply-chain-audit dive SCA-023` | Deep-dive into a numbered finding from a previous report |
| Help | `/supply-chain-audit help` | Show this help content |

Relative ranges accepted: `last N days`, `last N weeks`, `last N months`.

### Investigating Findings (Dive Mode)

Every finding in the report has a unique ID like `SCA-001`, `SCA-023`, etc. To investigate any finding:

```
/supply-chain-audit dive SCA-023
```

The agent will:
1. Look up the finding by ID in the cached `findings.json`
2. Show the full details: repo, category, risk level, commit SHA, PR link, evidence
3. Pull the relevant investigation steps from the detection-patterns reference
4. Offer to dig deeper — fetch the commit diff, check the PR timeline, look up advisories

This lets you triage the report interactively: scan the HTML dashboard, spot something concerning, then ask the agent to investigate it by number.

### Output Locations

| File | Purpose |
|------|---------|
| `.supply-chain-audit/cache/<hash>/findings.json` | All findings with IDs (SCA-NNN), structured for agent analysis |
| `.supply-chain-audit/cache/<hash>/findings_summary.json` | Aggregated summary for quick triage |
| `.supply-chain-audit/cache/<hash>/recommendations.json` | Agent-written top-10 security recommendations |
| `.supply-chain-audit/report.html` | Standalone HTML dashboard (no CDN deps) |

### Prerequisites

- `gh` CLI installed and authenticated
- `python3` 3.10+
- Network access to GitHub API and PyPI/npm/OSV.dev registries
