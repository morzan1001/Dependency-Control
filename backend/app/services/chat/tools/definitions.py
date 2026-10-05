"""Static tool metadata: TOOL_DEFINITIONS and TOOL_PERMISSIONS."""

from typing import Any, get_args

from app.core.constants import (
    DEFAULT_PQC_PLAN_ITEMS,
    MAX_COMPLIANCE_REPORT_PAGE,
    MAX_CRYPTO_HOTSPOT_PAGE,
    MAX_POLICY_AUDIT_PAGE,
    MAX_PQC_PLAN_ITEMS,
    ScopeName,
)
from app.core.permissions import Permissions
from app.models.finding import FindingType, Severity
from app.models.policy_audit_entry import PolicyType
from app.schemas.analytics import GroupBy, Metric
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ReportFramework

from ._helpers import MAX_CRYPTO_ASSET_PAGE, MAX_DAY_WINDOW, MAX_FINDING_ROWS, MAX_PLAN_STEPS, MAX_SUMMARY_ROWS

_DESC_PROJECT_ID = "The project ID"
_DESC_OPTIONAL_SINGLE_PROJECT = "Optional: restrict to a single project."
_DESC_OPTIONAL_SCAN_ID = (
    "Optional scan ID. Omit it to ask about the project's head build — the newest usable build on "
    "its default branch. Pass one only when the question is about that specific build; a scan ID "
    "taken from the top of get_scan_history is frequently a queued run or a deleted branch."
)
_DESC_ANSWER_NAMES_BUILD = "The result's 'scan' object names the build described and whether it is head."
_SEVERITIES = [s.value for s in Severity]
_FINDING_TYPES = [t.value for t in FindingType]
_SEVERITY_FILTER = {"type": "string", "enum": _SEVERITIES, "description": "Filter by severity."}
_FRAMEWORK = {"type": "string", "enum": [f.value for f in ReportFramework]}
_TYPE_FILTER = {
    "type": "string",
    "enum": _FINDING_TYPES,
    "description": "Filter by finding type. Typosquats are malware findings from the typosquatting scanner.",
}


def _bounded(default: int, maximum: int, noun: str) -> dict[str, Any]:
    """An integer argument that checked_arguments defaults and holds to [1, maximum]."""
    return {
        "type": "integer",
        "default": default,
        "minimum": 1,
        "maximum": maximum,
        "description": f"{noun} (default {default}, max {maximum}).",
    }


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_projects",
            "description": (
                "List projects the user can access, with their head build's severity stats and "
                "last scan date. For 'where should I start' "
                "use get_top_priority_findings or get_hotspots instead — those answer "
                "the prioritisation question directly."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "Optional case-insensitive substring filter on project name.",
                    },
                    "limit": _bounded(15, MAX_SUMMARY_ROWS, "Max projects"),
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_project_details",
            "description": (
                "Get a project's configuration: owning teams, default branch, active analyzers and their "
                "settings, SCM links, and the policies the system applies to it. retention is what "
                "housekeeping does to old scans (source global or project); 0 days or action 'none' keeps "
                "them forever. rescan_interval_hours is the scheduled rescan interval, null when rescans are "
                "off. license_policy is the effective license compliance policy. Members come from "
                "get_project_members; severity counts from get_scan_history."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_project_members",
            "description": (
                "Get everyone with access to a project: its direct members and the members of every owning "
                "team, each with username, role, effective_role and inherited_from (the granting teams)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan_history",
            "description": (
                "Get the scan history for a project, showing scan dates, status, and findings summary. "
                "Rows are newest-first across every branch and every status, so the first row is NOT "
                "the project's current build: the response's head_scan_id names that one, and the row "
                "it belongs to carries is_head=true."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                    "limit": _bounded(10, MAX_SUMMARY_ROWS, "Max scans"),
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan_details",
            "description": (
                "Get details of a scan: findings summary, stats, branch, commit, status. Describes the "
                f"project's head build unless scan_id says otherwise. {_DESC_ANSWER_NAMES_BUILD}"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": _DESC_OPTIONAL_SCAN_ID},
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan_findings",
            "description": (
                "Get findings from a scan, worst first, optionally filtered by severity or type. Answers "
                f"about the project's head build unless scan_id says otherwise. {_DESC_ANSWER_NAMES_BUILD} "
                "findings_total says how many findings match."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": _DESC_OPTIONAL_SCAN_ID},
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                    "severity": _SEVERITY_FILTER,
                    "type": _TYPE_FILTER,
                    "limit": _bounded(10, MAX_FINDING_ROWS, "Max findings"),
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_vulnerability_details",
            "description": (
                "Get details about a specific vulnerability/finding and its affected component. advisories lists "
                "the finding's worst advisories first, each with its own severity, CVSS, EPSS, KEV status and fix; "
                "advisories_total says how many it has."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "The finding ID"},
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["finding_id", "project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_findings",
            "description": (
                "Search the head-build findings of every project the user has access to. Use for cross-project "
                "queries like 'find all log4j vulnerabilities'. findings_total says how many findings match."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search term (CVE ID, package name, description keyword)",
                    },
                    "severity": _SEVERITY_FILTER,
                    "type": _TYPE_FILTER,
                    "limit": _bounded(10, MAX_FINDING_ROWS, "Max findings"),
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings_by_severity",
            "description": "Count the unwaived findings of a project's head build, grouped by severity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings_by_type",
            "description": "Count the unwaived findings of a project's head build, grouped by finding type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_analytics_summary",
            "description": (
                "Org-wide posture: total counts by severity + top 3 risky projects. "
                "Use for a high-level overview question, NOT for 'what should I fix' — "
                "for that prefer get_top_priority_findings or get_kev_findings. Call "
                "at most once per user question."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_risk_trends",
            "description": (
                "How vulnerability counts changed over time on each project's head branch. One point per "
                "period, newest first: bucket names the period (day up to 14 days, week up to 90, month "
                "beyond). A point sums the last usable head-branch build of each project in that period; "
                "risk_score is their average and projects says how many built in it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Optional: limit to a specific project"},
                    "days": _bounded(30, MAX_DAY_WINDOW, "Days to look back"),
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_dependency_tree",
            "description": (
                "List a project's head-build dependencies as a flat list, direct dependencies first, then by "
                "name. Each row names up to 5 of its parents and its parent_count; dependencies_total counts "
                "every dependency the filter matches."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                    "limit": _bounded(40, MAX_SUMMARY_ROWS, "Max dependencies"),
                    "direct_only": {"type": "boolean", "description": "Only the direct dependencies."},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_hotspots",
            "description": (
                "The riskiest projects the user can access, worst first by their head build's critical "
                "then high count, each with its head_scan_id and severity stats. For the riskiest "
                "libraries use search_findings or find_component_usage."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": _bounded(10, MAX_SUMMARY_ROWS, "Max hotspots"),
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_dependency_details",
            "description": (
                "Get enrichment metadata for one package version (lookup by PURL, or by name, which returns one "
                "matching version): license and license risks, homepage/repository links, deps.dev popularity "
                "(stars, forks, dependents), OpenSSF scorecard, publish date, deprecation flag and known "
                "advisory IDs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "dependency_name": {"type": "string", "description": "The dependency/package name (or PURL)"},
                },
                "required": ["dependency_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_teams",
            "description": "List the teams the user can read.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_team_details",
            "description": "Get details about a team including its members and their roles.",
            "parameters": {
                "type": "object",
                "properties": {
                    "team_id": {"type": "string", "description": "The team ID"},
                },
                "required": ["team_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_team_projects",
            "description": "Get a team's projects with their head build's severity stats and last scan date.",
            "parameters": {
                "type": "object",
                "properties": {
                    "team_id": {"type": "string", "description": "The team ID"},
                },
                "required": ["team_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_waiver_status",
            "description": (
                "Check whether a finding is currently SUPPRESSED by a waiver in the head build. "
                "Returns one entry per matching finding (a finding id such as a license id can cover "
                "several components) with the advisories a per-CVE waiver suppresses; waived is true "
                "only when it is waived on every one of them (for an advisory ID: that advisory). "
                "Returns waived:false with waiver_present:true "
                "and suppressing:false when an active waiver exists but the finding is not in the head "
                "build (fixed/moved/renamed or the waiver is dormant)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "The finding ID, or a CVE/advisory ID to check its per-advisory waivers",
                    },
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["finding_id", "project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_project_waivers",
            "description": "List all waivers for a project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_global_waivers",
            "description": "List all global waivers that apply across all projects.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_top_priority_findings",
            "description": (
                "Return the top N most urgent unwaived CRITICAL/HIGH findings across ALL accessible "
                "projects: actively exploited ones first, then CRITICAL before HIGH, each group by EPSS "
                "score and highest advisory CVSS. Use this when the user asks 'where should I start?', "
                "'what should I fix first?' or 'which project has the biggest problem?'. Returns a "
                "compact list with finding_id, severity, CVE, affected component and fixed_version, "
                "so you can give an actionable answer in a single turn."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": _bounded(5, MAX_FINDING_ROWS, "Max findings"),
                    "project_id": {
                        "type": "string",
                        "description": _DESC_OPTIONAL_SINGLE_PROJECT,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_remediation_plan",
            "description": (
                "Generate a step-by-step remediation plan for a project. Groups CRITICAL/HIGH "
                "vulnerability and end-of-life findings by installed component version, picks the "
                "smallest upgrade that fixes all of its CVEs, preferring the installed major line, "
                "flags direct vs. transitive dependencies and breaking-change risk (major version "
                "bumps). Use this when the user asks 'how do I fix everything', 'build me a plan', "
                "'what's the upgrade path', or similar holistic remediation questions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                    "max_steps": _bounded(10, MAX_PLAN_STEPS, "Max plan steps"),
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_auto_fixable_findings",
            "description": (
                "Return CRITICAL/HIGH vulnerability findings whose every live CRITICAL/HIGH advisory has "
                "a fix — the 'low-hanging fruit' a team can resolve with a dependency bump. "
                "quick_fix_version is the smallest such bump, on the installed major line where one "
                "exists; breaking_change_risk 'high' marks a major upgrade. "
                "still_open names the lower-severity advisories the bump leaves open. "
                "Use when the user asks 'what quick wins do I have?', 'what can I fix "
                "easily?' or 'which updates are available?'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_OPTIONAL_SINGLE_PROJECT},
                    "limit": _bounded(10, MAX_FINDING_ROWS, "Max findings"),
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_waiver_for_finding",
            "description": (
                "Draft a waiver justification for a specific finding based on reachability, "
                "severity, EPSS and fix availability. Use when the user says 'should we "
                "waive this?' or 'help me write a waiver for finding X'. Returns a "
                "suggested reason + recommended expiry, NOT a stored waiver."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "The finding identifier (component:version)."},
                    "project_id": {"type": "string", "description": "The project that owns the finding."},
                },
                "required": ["finding_id", "project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compare_scans",
            "description": (
                "Compare two scans of the same project for findings, components or cryptographic "
                "assets. Returns a paginated delta envelope: 'totals' counts added/removed/unchanged "
                "(findings and components also changed), and 'items' carry 'change'. to_scan_id defaults to the "
                "head build and from_scan_id to the build before to_scan_id on its branch. Items list "
                "added before removed: pass change='removed' for resolved findings and page for later "
                "pages. Use when the user asks 'what changed since my last deploy?', 'did the last "
                "scan introduce new vulns?', 'which findings did we resolve?' or what crypto changed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID."},
                    "from_scan_id": {"type": "string", "description": "Optional baseline scan."},
                    "to_scan_id": {"type": "string", "description": "Optional target scan."},
                    "category": {"type": "string", "enum": ["findings", "components", "crypto"]},
                    "change": {
                        "type": "string",
                        "enum": ["added", "removed", "changed", "all"],
                        "description": "Optional: only items of this change; crypto has no 'changed' items.",
                    },
                    "severity": {
                        "type": "array",
                        "items": {"type": "string", "enum": _SEVERITIES},
                        "description": "Optional: restrict findings to these severities.",
                    },
                    "finding_type": {
                        "type": "array",
                        "items": {"type": "string", "enum": _FINDING_TYPES},
                        "description": "Optional: restrict findings to these finding types.",
                    },
                    "page": {"type": "integer", "minimum": 1, "description": "Page number (default 1)."},
                    "page_size": _bounded(20, MAX_FINDING_ROWS, "Items per page"),
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_kev_findings",
            "description": (
                "Return findings with an unwaived advisory in CISA KEV, i.e. ACTIVELY "
                "EXPLOITED in the wild; each row's cve names that advisory. These "
                "should always be prioritised over a CVSS-based order. Use when the "
                "user asks 'what is actively exploited?', 'which findings are in KEV?' "
                "or 'show me the stuff with real-world exploits'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_OPTIONAL_SINGLE_PROJECT},
                    "limit": _bounded(10, MAX_FINDING_ROWS, "Max findings"),
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_component_usage",
            "description": (
                "Find every authorized project that currently ships a given package/library "
                "(e.g. 'log4j-core', 'openssl'). Optionally constrain to one version. Use "
                "when the user asks 'where do we use X?', 'which projects are affected by "
                "a zero-day in Y?' or during incident scoping. Scans ONLY the head build "
                "per project, not historical data."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "component_name": {
                        "type": "string",
                        "description": "Package name (substring match, case-insensitive).",
                    },
                    "version": {"type": "string", "description": "Optional: exact version."},
                },
                "required": ["component_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings_by_cve",
            "description": (
                "Find every finding that refers to a specific CVE across the user's "
                "projects. Use when the user mentions a concrete CVE ID. Matches the exact "
                "id under any of an advisory's identifiers (id, aliases, resolved CVE), not free-text."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "e.g. 'CVE-2024-12345'."},
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_cve_details",
            "description": (
                "Return enriched information about a CVE ID: description, CVSS score, "
                "EPSS, KEV status, exploit_maturity, fix version, external references. Read "
                "from one occurrence in the user's projects; its fixed_version applies to "
                "affected_component only, so use get_findings_by_cve for every affected "
                "component. Use when the user asks 'tell me about CVE-X' or 'is CVE-X exploitable?'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "e.g. 'CVE-2024-12345'."},
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_stale_findings",
            "description": (
                "Return unwaived findings in the head build that were first seen more than N days "
                "ago in the project, the age the CVE SLA report uses; each row carries first_seen_at. "
                "Use when the user asks 'what vulns have we been ignoring?', 'what's old?' or about SLA."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "days_open": _bounded(30, MAX_DAY_WINDOW, "Minimum open age in days"),
                    "project_id": {"type": "string", "description": "Optional: restrict to one project."},
                    "severity_min": {
                        "type": "string",
                        "description": "Min severity, one of CRITICAL/HIGH/MEDIUM/LOW (default HIGH).",
                    },
                    "limit": _bounded(10, MAX_FINDING_ROWS, "Max findings"),
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_license_violations",
            "description": (
                "Return unwaived license-compliance findings specifically (type=license). Use "
                "when the user asks about legal / license issues, e.g. 'do we have GPL "
                "in proprietary code?' or 'license violations across the org'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Optional: one project."},
                    "limit": _bounded(10, MAX_FINDING_ROWS, "Max findings"),
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_expiring_waivers",
            "description": (
                "List waivers whose expiration_date falls in the next N days so an "
                "admin can re-review them before they silently expire. Use when the "
                "user asks 'which waivers need renewal?' or about waiver hygiene."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "days": _bounded(30, MAX_DAY_WINDOW, "Look-ahead window in days"),
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_team_risk_overview",
            "description": (
                "Aggregate security posture for a single team: severity totals over its projects' head "
                "builds plus the three riskiest projects (critical, then high). Use when the user asks "
                "'how is team X doing?' or 'team-level summary'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "team_id": {"type": "string", "description": "The team ID."},
                },
                "required": ["team_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_projects_without_recent_scan",
            "description": (
                "List projects whose last scan is older than N days (or which have "
                "never been scanned). Use when the user asks 'which projects are we "
                "neglecting?' or 'where is our scan coverage lagging?'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "days": _bounded(14, MAX_DAY_WINDOW, "Threshold in days"),
                    "limit": _bounded(10, MAX_SUMMARY_ROWS, "Max projects"),
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_callgraph",
            "description": (
                "Summarise a project's most recently uploaded call graph per language: module usage "
                "(import and call counts per module) and totals. A graph comes from whichever build "
                "last uploaded one, which can be another branch or an older build than head; its branch, "
                "scan_id and updated_at name that build, so state them. For whether a specific finding "
                "is reachable, use check_reachability."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                    "language": {
                        "type": "string",
                        "description": "Optional: only this language's graph, e.g. python, typescript, go, java.",
                    },
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_reachability",
            "description": "Check whether a specific vulnerability is reachable through the application's call graph.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "The finding/vulnerability ID"},
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["finding_id", "project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_archives",
            "description": "List archived scans.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Optional: filter by project"},
                    "limit": _bounded(20, MAX_SUMMARY_ROWS, "Max archives"),
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_archive_details",
            "description": "Get details of an archived scan.",
            "parameters": {
                "type": "object",
                "properties": {
                    "archive_id": {"type": "string", "description": "The archive ID"},
                },
                "required": ["archive_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_project_webhooks",
            "description": "List webhook configurations for a project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_webhook_deliveries",
            "description": "Get delivery history for a webhook, showing successes and failures.",
            "parameters": {
                "type": "object",
                "properties": {
                    "webhook_id": {"type": "string", "description": "The webhook ID"},
                },
                "required": ["webhook_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_crypto_assets",
            "description": (
                "List cryptographic assets ingested for a build, filterable by asset_type, primitive "
                "and name_search. Lists the project's head build unless scan_id says otherwise. "
                f"{_DESC_ANSWER_NAMES_BUILD}"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                    "scan_id": {"type": "string", "description": _DESC_OPTIONAL_SCAN_ID},
                    "asset_type": {
                        "type": "string",
                        "enum": [t.value for t in CryptoAssetType],
                        "description": "Optional filter by asset type",
                    },
                    "primitive": {
                        "type": "string",
                        "enum": [p.value for p in CryptoPrimitive],
                        "description": "Optional filter by primitive",
                    },
                    "name_search": {"type": "string", "description": "Optional substring filter on asset name"},
                    "skip": {"type": "integer", "description": "Number of items to skip (default 0)"},
                    "limit": _bounded(100, MAX_CRYPTO_ASSET_PAGE, "Max assets"),
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_crypto_asset_details",
            "description": "Get full details of a single cryptographic asset by its ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                    "asset_id": {"type": "string", "description": "The crypto asset ID"},
                },
                "required": ["project_id", "asset_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_crypto_summary",
            "description": (
                "Get a summary of cryptographic assets broken down by asset type. Summarises the "
                f"project's head build unless scan_id says otherwise. {_DESC_ANSWER_NAMES_BUILD}"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                    "scan_id": {"type": "string", "description": _DESC_OPTIONAL_SCAN_ID},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_project_crypto_policy",
            "description": (
                "Get the effective cryptographic policy rules for a project: the system rules with "
                "the project's override merged in. override_locked=true means a global policy "
                "disables project overrides, so suggest none for this project."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_crypto_policy_override",
            "description": (
                "Advisory: returns the enabled crypto policy rules that match the most findings. Reads "
                "the project's head build unless scan_id says otherwise. Does NOT make any changes — "
                "the caller decides whether to craft a project-scoped override based on the "
                f"suggestions. {_DESC_ANSWER_NAMES_BUILD}"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": _DESC_PROJECT_ID},
                    "scan_id": {"type": "string", "description": _DESC_OPTIONAL_SCAN_ID},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_crypto_hotspots",
            "description": "List top crypto hotspots for a project, grouped by the given dimension.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "group_by": {"type": "string", "enum": list(get_args(GroupBy)), "default": "name"},
                    "limit": _bounded(20, MAX_CRYPTO_HOTSPOT_PAGE, "Max hotspots"),
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_crypto_trends",
            "description": (
                "Return time-bucketed crypto finding/asset trend data for a project. "
                "Bucket granularity is auto-selected based on the days range."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "metric": {"type": "string", "enum": list(get_args(Metric)), "default": "total_crypto_findings"},
                    "days": _bounded(30, MAX_DAY_WINDOW, "Days to look back"),
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_settings",
            "description": "Get current system-wide configuration.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_health",
            "description": "Get cache health and statistics.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_pqc_migration_plan",
            "description": "Generate a PQC migration plan for one project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "limit": _bounded(DEFAULT_PQC_PLAN_ITEMS, MAX_PQC_PLAN_ITEMS, "Max plan items"),
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_compliance_reports",
            "description": "List recent compliance reports (metadata only).",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "framework": _FRAMEWORK,
                    "limit": _bounded(10, MAX_COMPLIANCE_REPORT_PAGE, "Max reports"),
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_policy_audit_entries",
            "description": (
                "List the change history of the crypto policy or the license policy. License policy history "
                "exists only at project scope; policy_scope=project requires project_id."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "policy_scope": {"type": "string", "enum": ["system", "project"]},
                    "policy_type": {"type": "string", "enum": list(get_args(PolicyType)), "default": "crypto"},
                    "project_id": {"type": "string"},
                    "limit": _bounded(20, MAX_POLICY_AUDIT_PAGE, "Max entries"),
                },
                "required": ["policy_scope"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_framework_evaluation_summary",
            "description": (
                "Evaluate a compliance framework (crypto standards, the PQC migration plan, the license audit "
                "or the CVE remediation SLA) and return summary counts."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "enum": list(get_args(ScopeName))},
                    "scope_id": {"type": "string"},
                    "framework": _FRAMEWORK,
                },
                "required": ["scope", "framework"],
            },
        },
    },
]


_TEAM_READ = [Permissions.TEAM_READ, Permissions.TEAM_READ_ALL]
_WAIVER_READ = [Permissions.WAIVER_READ, Permissions.WAIVER_READ_ALL]
_ARCHIVE_READ = [Permissions.ARCHIVE_READ, Permissions.ARCHIVE_READ_ALL]
# The same any-of pair require_analytics_permission checks on the matching REST route.
_ANALYTICS_SEARCH = [Permissions.ANALYTICS_READ, Permissions.ANALYTICS_SEARCH]

TOOL_PERMISSIONS: dict[str, list[str]] = {
    # Any-of, checked before the handler runs; the handler still applies the per-resource rule.
    "search_findings": _ANALYTICS_SEARCH,
    "get_findings_by_cve": _ANALYTICS_SEARCH,
    "get_cve_details": _ANALYTICS_SEARCH,
    "find_component_usage": _ANALYTICS_SEARCH,
    "generate_remediation_plan": [Permissions.ANALYTICS_READ, Permissions.ANALYTICS_RECOMMENDATIONS],
    "get_analytics_summary": [Permissions.ANALYTICS_READ, Permissions.ANALYTICS_SUMMARY],
    "list_teams": _TEAM_READ,
    "get_team_details": _TEAM_READ,
    "get_team_projects": _TEAM_READ,
    "get_team_risk_overview": _TEAM_READ,
    "list_project_waivers": _WAIVER_READ,
    "list_global_waivers": _WAIVER_READ,
    "get_waiver_status": _WAIVER_READ,
    "get_expiring_waivers": _WAIVER_READ,
    "get_system_settings": [Permissions.SYSTEM_MANAGE],
    "get_system_health": [Permissions.SYSTEM_MANAGE],
    "list_archives": _ARCHIVE_READ,
    "get_archive_details": _ARCHIVE_READ,
}
