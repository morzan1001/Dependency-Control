from collections.abc import Sequence
from typing import Any, get_args

from app.core.constants import (
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

TOOL_DEFINITIONS: list[dict[str, Any]] = []
TOOL_PERMISSIONS: dict[str, list[str]] = {}


def _tool(
    name: str,
    description: str,
    *,
    required: Sequence[str] = (),
    permissions: list[str] | None = None,
    **properties: dict[str, Any],
) -> None:
    """`permissions` are any-of and checked before the handler, which still applies the per-resource rule."""
    TOOL_DEFINITIONS.append(
        {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": {"type": "object", "properties": properties, "required": list(required)},
            },
        }
    )
    if permissions:
        TOOL_PERMISSIONS[name] = permissions


def _string(description: str | None = None) -> dict[str, Any]:
    return {"type": "string", **({"description": description} if description else {})}


def _bounded(default: int, maximum: int, noun: str) -> dict[str, Any]:
    return {
        "type": "integer",
        "default": default,
        "minimum": 1,
        "maximum": maximum,
        "description": f"{noun} (default {default}, max {maximum}).",
    }


_ANSWER_NAMES_BUILD = "The result's 'scan' object names the build described and whether it is head."
_SEVERITIES = [s.value for s in Severity]
_FINDING_TYPES = [t.value for t in FindingType]

_PROJECT_ID = _string("The project ID")
_ONE_PROJECT = _string("Optional: restrict to a single project.")
_SCAN_ID = _string(
    "Optional scan ID. Omit it to ask about the project's head build — the newest usable build on "
    "its default branch. Pass one only when the question is about that specific build; a scan ID "
    "taken from the top of get_scan_history is frequently a queued run or a deleted branch."
)
_FINDING_ROW_ID = _string("A finding row's finding_id (component:version) or its id")
_TEAM_ID = _string("The team ID")
_CVE_ID = _string("e.g. 'CVE-2024-12345'.")
_SEVERITY_FILTER = {"type": "string", "enum": _SEVERITIES, "description": "Filter by severity."}
_TYPE_FILTER = {
    "type": "string",
    "enum": _FINDING_TYPES,
    "description": "Filter by finding type. Typosquats are malware findings from the typosquatting scanner.",
}
_FRAMEWORK = {"type": "string", "enum": [f.value for f in ReportFramework]}
_FINDING_LIMIT = _bounded(10, MAX_FINDING_ROWS, "Max findings")

_TEAM_READ = [Permissions.TEAM_READ, Permissions.TEAM_READ_ALL]
_WAIVER_READ = [Permissions.WAIVER_READ, Permissions.WAIVER_READ_ALL]
_ARCHIVE_READ = [Permissions.ARCHIVE_READ, Permissions.ARCHIVE_READ_ALL]
_SYSTEM_MANAGE = [Permissions.SYSTEM_MANAGE]
# The same any-of pair require_analytics_permission checks on the matching REST route.
_ANALYTICS_SEARCH = [Permissions.ANALYTICS_READ, Permissions.ANALYTICS_SEARCH]

_tool(
    "list_projects",
    "List projects the user can access, with their head build's severity stats and "
    "last scan date. For 'where should I start' "
    "use get_top_priority_findings or get_hotspots instead — those answer "
    "the prioritisation question directly.",
    search=_string("Optional case-insensitive substring filter on project name."),
    limit=_bounded(15, MAX_SUMMARY_ROWS, "Max projects"),
)
_tool(
    "get_project_details",
    "Get a project's configuration: owning teams, default branch, active analyzers and their "
    "settings, SCM links, and the policies the system applies to it. retention is what "
    "housekeeping does to old scans (source global or project); 0 days or action 'none' keeps "
    "them forever. rescan_interval_hours is the scheduled rescan interval, null when rescans are "
    "off. license_policy is the effective license compliance policy. Members come from "
    "get_project_members; severity counts from get_scan_history.",
    required=["project_id"],
    project_id=_PROJECT_ID,
)
_tool(
    "get_project_members",
    "Get everyone with access to a project: its direct members and the members of every owning "
    "team, each with username, role, effective_role and inherited_from (the granting teams).",
    required=["project_id"],
    project_id=_PROJECT_ID,
)
_tool(
    "get_scan_history",
    "Get the scan history for a project, showing scan dates, status, and findings summary. "
    "Rows are newest-first across every branch and every status, so the first row is NOT "
    "the project's current build: the response's head_scan_id names that one, and the row "
    "it belongs to carries is_head=true.",
    required=["project_id"],
    project_id=_PROJECT_ID,
    limit=_bounded(10, MAX_SUMMARY_ROWS, "Max scans"),
)
_tool(
    "get_scan_details",
    "Get details of a scan: status, branch, commit, timing, finding counts and failed analyzers. "
    f"Describes the project's head build unless scan_id says otherwise. {_ANSWER_NAMES_BUILD}",
    required=["project_id"],
    scan_id=_SCAN_ID,
    project_id=_PROJECT_ID,
)
_tool(
    "get_scan_findings",
    "Get findings from a scan, worst first, optionally filtered by severity or type. Answers "
    f"about the project's head build unless scan_id says otherwise. {_ANSWER_NAMES_BUILD} "
    "findings_total says how many findings match.",
    required=["project_id"],
    scan_id=_SCAN_ID,
    project_id=_PROJECT_ID,
    severity=_SEVERITY_FILTER,
    type=_TYPE_FILTER,
    limit=_FINDING_LIMIT,
)
_tool(
    "get_vulnerability_details",
    "Get details about a specific vulnerability/finding and its affected component. advisories lists "
    "the finding's worst advisories first, each with its own severity, CVSS, EPSS, KEV status and fix; "
    "advisories_total says how many it has.",
    required=["finding_id", "project_id"],
    finding_id=_FINDING_ROW_ID,
    project_id=_PROJECT_ID,
)
_tool(
    "search_findings",
    "Search the head-build findings of every project the user has access to, worst first. Use for "
    "cross-project queries like 'find all log4j vulnerabilities'. findings_total says how many findings match.",
    required=["query"],
    permissions=_ANALYTICS_SEARCH,
    query=_string("Search term (CVE ID, package name, description keyword)"),
    severity=_SEVERITY_FILTER,
    type=_TYPE_FILTER,
    limit=_FINDING_LIMIT,
)
_tool(
    "get_findings_by_severity",
    "Count the unwaived findings of a project's head build, grouped by severity.",
    required=["project_id"],
    project_id=_PROJECT_ID,
)
_tool(
    "get_findings_by_type",
    "Count the unwaived findings of a project's head build, grouped by finding type.",
    required=["project_id"],
    project_id=_PROJECT_ID,
)
_tool(
    "get_analytics_summary",
    "Org-wide posture: total counts by severity + top 3 risky projects. "
    "Use for a high-level overview question, NOT for 'what should I fix' — "
    "for that prefer get_top_priority_findings or get_kev_findings. Call "
    "at most once per user question.",
    permissions=[Permissions.ANALYTICS_READ, Permissions.ANALYTICS_SUMMARY],
)
_tool(
    "get_risk_trends",
    "How vulnerability counts changed over time on each project's head branch. One point per "
    "period, newest first: bucket names the period (day up to 14 days, week up to 90, month "
    "beyond). A point sums the last usable head-branch build of each project in that period; "
    "risk_score is their average and projects says how many built in it.",
    project_id=_ONE_PROJECT,
    days=_bounded(30, MAX_DAY_WINDOW, "Days to look back"),
)
_tool(
    "get_dependency_tree",
    "List a project's head-build dependencies as a flat list, direct dependencies first, then by "
    "name. Each row names up to 5 of its parents and its parent_count; dependencies_total counts "
    "every dependency the filter matches.",
    required=["project_id"],
    project_id=_PROJECT_ID,
    limit=_bounded(40, MAX_SUMMARY_ROWS, "Max dependencies"),
    direct_only={"type": "boolean", "description": "Only the direct dependencies."},
)
_tool(
    "get_hotspots",
    "The riskiest projects the user can access, worst first by their head build's risk_score "
    "as the dashboard ranks them, each with its head_scan_id and severity stats. For the riskiest "
    "libraries use search_findings or find_component_usage.",
    limit=_bounded(10, MAX_SUMMARY_ROWS, "Max hotspots"),
)
_tool(
    "get_dependency_details",
    "Get enrichment metadata for one package version (lookup by PURL, or by name, which returns one "
    "matching version): license and license risks, homepage/repository links, deps.dev popularity "
    "(stars, forks, dependents), OpenSSF scorecard, publish date, deprecation flag and known "
    "advisory IDs.",
    required=["dependency_name"],
    dependency_name=_string("The dependency/package name (or PURL)"),
)
_tool("list_teams", "List the teams the user can read.", permissions=_TEAM_READ)
_tool(
    "get_team_details",
    "Get details about a team including its members and their roles.",
    required=["team_id"],
    permissions=_TEAM_READ,
    team_id=_TEAM_ID,
)
_tool(
    "get_team_projects",
    "Get a team's projects with their head build's severity stats and last scan date.",
    required=["team_id"],
    permissions=_TEAM_READ,
    team_id=_TEAM_ID,
)
_tool(
    "get_waiver_status",
    "Check whether a finding is currently SUPPRESSED by a waiver in the head build. "
    "Returns one entry per matching finding (a finding id such as a license id can cover "
    "several components) with the advisories a per-CVE waiver suppresses; waived is true "
    "only when it is waived on every one of them (for an advisory ID: that advisory). "
    "Returns waived:false with waiver_present:true "
    "and suppressing:false when an active waiver exists but the finding is not in the head "
    "build (fixed/moved/renamed or the waiver is dormant).",
    required=["finding_id", "project_id"],
    permissions=_WAIVER_READ,
    finding_id=_string("The finding ID, or a CVE/advisory ID to check its per-advisory waivers"),
    project_id=_PROJECT_ID,
)
_tool(
    "list_project_waivers",
    "List all waivers for a project.",
    required=["project_id"],
    permissions=_WAIVER_READ,
    project_id=_PROJECT_ID,
)
_tool("list_global_waivers", "List all global waivers that apply across all projects.", permissions=_WAIVER_READ)
_tool(
    "get_top_priority_findings",
    "Return the top N most urgent unwaived CRITICAL/HIGH findings across ALL accessible "
    "projects: actively exploited ones first, then CRITICAL before HIGH, each group by EPSS "
    "score and highest advisory CVSS. Use this when the user asks 'where should I start?', "
    "'what should I fix first?' or 'which project has the biggest problem?'. Returns a "
    "compact list with finding_id, severity, CVE, affected component and fixed_version, "
    "so you can give an actionable answer in a single turn.",
    limit=_bounded(5, MAX_FINDING_ROWS, "Max findings"),
    project_id=_ONE_PROJECT,
)
_tool(
    "generate_remediation_plan",
    "Generate a step-by-step remediation plan for a project. Groups CRITICAL/HIGH "
    "vulnerability and end-of-life findings by installed component version, picks the "
    "smallest upgrade that fixes all of its CVEs, preferring the installed major line, "
    "flags direct vs. transitive dependencies and breaking-change risk (major version "
    "bumps). Use this when the user asks 'how do I fix everything', 'build me a plan', "
    "'what's the upgrade path', or similar holistic remediation questions.",
    required=["project_id"],
    permissions=[Permissions.ANALYTICS_READ, Permissions.ANALYTICS_RECOMMENDATIONS],
    project_id=_PROJECT_ID,
    max_steps=_bounded(10, MAX_PLAN_STEPS, "Max plan steps"),
)
_tool(
    "get_auto_fixable_findings",
    "Return CRITICAL/HIGH vulnerability findings whose every live CRITICAL/HIGH advisory has "
    "a fix — the 'low-hanging fruit' a team can resolve with a dependency bump. "
    "quick_fix_version is the smallest such bump, on the installed major line where one "
    "exists; breaking_change_risk 'high' marks a major upgrade. "
    "still_open names the lower-severity advisories the bump leaves open. "
    "Use when the user asks 'what quick wins do I have?', 'what can I fix "
    "easily?' or 'which updates are available?'.",
    project_id=_ONE_PROJECT,
    limit=_FINDING_LIMIT,
)
_tool(
    "suggest_waiver_for_finding",
    "Draft a waiver justification for a specific finding based on reachability, "
    "severity, EPSS and fix availability. Use when the user says 'should we "
    "waive this?' or 'help me write a waiver for finding X'. Returns a "
    "suggested reason + recommended expiry, NOT a stored waiver. Reads the finding on the "
    f"project's head build unless scan_id says otherwise. {_ANSWER_NAMES_BUILD}",
    required=["finding_id", "project_id"],
    finding_id=_string("The finding identifier (component:version)."),
    project_id=_string("The project that owns the finding."),
    scan_id=_SCAN_ID,
)
_tool(
    "compare_scans",
    "Compare two scans of the same project for findings, components or cryptographic "
    "assets. Returns a paginated delta envelope: 'totals' counts added/removed/unchanged "
    "(findings and components also changed), and 'items' carry 'change'. to_scan_id defaults to the "
    "head build and from_scan_id to the build before to_scan_id on its branch. Items list "
    "added before removed: pass change='removed' for resolved findings and page for later "
    "pages. Use when the user asks 'what changed since my last deploy?', 'did the last "
    "scan introduce new vulns?', 'which findings did we resolve?' or what crypto changed.",
    required=["project_id"],
    project_id=_PROJECT_ID,
    from_scan_id=_string("Optional baseline scan."),
    to_scan_id=_string("Optional target scan."),
    category={"type": "string", "enum": ["findings", "components", "crypto"]},
    change={
        "type": "string",
        "enum": ["added", "removed", "changed", "all"],
        "description": "Optional: only items of this change; crypto has no 'changed' items.",
    },
    severity={
        "type": "array",
        "items": {"type": "string", "enum": _SEVERITIES},
        "description": "Optional: restrict findings to these severities.",
    },
    finding_type={
        "type": "array",
        "items": {"type": "string", "enum": _FINDING_TYPES},
        "description": "Optional: restrict findings to these finding types.",
    },
    page={"type": "integer", "minimum": 1, "description": "Page number (default 1)."},
    page_size=_bounded(20, MAX_FINDING_ROWS, "Items per page"),
)
_tool(
    "get_kev_findings",
    "Return findings with an unwaived advisory in CISA KEV, i.e. ACTIVELY "
    "EXPLOITED in the wild; each row's cve names that advisory. These "
    "should always be prioritised over a CVSS-based order. Use when the "
    "user asks 'what is actively exploited?', 'which findings are in KEV?' "
    "or 'show me the stuff with real-world exploits'.",
    project_id=_ONE_PROJECT,
    limit=_FINDING_LIMIT,
)
_tool(
    "find_component_usage",
    "Find every authorized project that currently ships a given package/library "
    "(e.g. 'log4j-core', 'openssl'). Optionally constrain to one version. Use "
    "when the user asks 'where do we use X?', 'which projects are affected by "
    "a zero-day in Y?' or during incident scoping. Scans ONLY the head build "
    "per project, not historical data.",
    required=["component_name"],
    permissions=_ANALYTICS_SEARCH,
    component_name=_string("Package name (substring match, case-insensitive)."),
    version=_string("Optional: exact version."),
)
_tool(
    "get_findings_by_cve",
    "List every one of the user's projects a specific CVE occurs in, with its occurrence "
    "count and sample findings. Use when the user mentions a concrete CVE ID. Matches the exact "
    "id under any of an advisory's identifiers (id, aliases, resolved CVE), not free-text.",
    required=["cve_id"],
    permissions=_ANALYTICS_SEARCH,
    cve_id=_CVE_ID,
    project_id=_ONE_PROJECT,
)
_tool(
    "get_cve_details",
    "Return enriched information about a CVE ID: description, CVSS score, "
    "EPSS, KEV status, exploit_maturity, fix version, external references. Read "
    "from one occurrence in the user's projects; its fixed_version applies to "
    "affected_component only, so use get_findings_by_cve for every affected "
    "component. Use when the user asks 'tell me about CVE-X' or 'is CVE-X exploitable?'.",
    required=["cve_id"],
    permissions=_ANALYTICS_SEARCH,
    cve_id=_CVE_ID,
)
_tool(
    "get_stale_findings",
    "Return unwaived findings in the head build that were first seen more than N days "
    "ago in the project, the age the CVE SLA report uses; each row carries first_seen_at. "
    "Use when the user asks 'what vulns have we been ignoring?', 'what's old?' or about SLA.",
    days_open=_bounded(30, MAX_DAY_WINDOW, "Minimum open age in days"),
    project_id=_ONE_PROJECT,
    severity_min=_string("Min severity, one of CRITICAL/HIGH/MEDIUM/LOW (default HIGH)."),
    limit=_FINDING_LIMIT,
)
_tool(
    "get_license_violations",
    "Return unwaived license-compliance findings specifically (type=license). Use "
    "when the user asks about legal / license issues, e.g. 'do we have GPL "
    "in proprietary code?' or 'license violations across the org'.",
    project_id=_ONE_PROJECT,
    limit=_FINDING_LIMIT,
)
_tool(
    "get_expiring_waivers",
    "List waivers whose expiration_date falls in the next N days so an "
    "admin can re-review them before they silently expire. Use when the "
    "user asks 'which waivers need renewal?' or about waiver hygiene.",
    permissions=_WAIVER_READ,
    days=_bounded(30, MAX_DAY_WINDOW, "Look-ahead window in days"),
)
_tool(
    "get_team_risk_overview",
    "Aggregate security posture for a single team: severity totals over its projects' head "
    "builds plus the three riskiest projects by risk_score. Use when the user asks "
    "'how is team X doing?' or 'team-level summary'.",
    required=["team_id"],
    permissions=_TEAM_READ,
    team_id=_TEAM_ID,
)
_tool(
    "get_projects_without_recent_scan",
    "List projects whose last scan is older than N days (or which have "
    "never been scanned). Use when the user asks 'which projects are we "
    "neglecting?' or 'where is our scan coverage lagging?'.",
    days=_bounded(14, MAX_DAY_WINDOW, "Threshold in days"),
    limit=_bounded(10, MAX_SUMMARY_ROWS, "Max projects"),
)
_tool(
    "get_callgraph",
    "Summarise a project's most recently uploaded call graph per language: per-module import and call "
    "counts with each module's importing files and used symbols, and totals. A graph too large for the "
    "answer lists counts only, busiest first, and only its busiest modules if still too large "
    "(module_usage_total counts all). A graph comes from whichever build last uploaded one, which can "
    "be another branch or an older build than head; its branch, scan_id and updated_at name that "
    "build, so state them. For whether a specific finding is reachable, use check_reachability.",
    required=["project_id"],
    project_id=_PROJECT_ID,
    language=_string("Optional: only this language's graph, e.g. python, typescript, go, java."),
)
_tool(
    "check_reachability",
    "Check whether a specific vulnerability is reachable through the application's call graph.",
    required=["finding_id", "project_id"],
    finding_id=_FINDING_ROW_ID,
    project_id=_PROJECT_ID,
)
_tool(
    "list_archives",
    "List archived scans.",
    permissions=_ARCHIVE_READ,
    project_id=_ONE_PROJECT,
    limit=_bounded(20, MAX_SUMMARY_ROWS, "Max archives"),
)
_tool(
    "get_archive_details",
    "Get details of an archived scan.",
    required=["archive_id"],
    permissions=_ARCHIVE_READ,
    archive_id=_string("The archive ID"),
)
_tool(
    "list_project_webhooks",
    "List webhook configurations for a project.",
    required=["project_id"],
    project_id=_PROJECT_ID,
)
_tool(
    "get_webhook_deliveries",
    "Get delivery history for a webhook, showing successes and failures.",
    required=["webhook_id"],
    webhook_id=_string("The webhook ID"),
)
_tool(
    "list_crypto_assets",
    "List cryptographic assets ingested for a build, filterable by asset_type, primitive "
    "and name_search. Lists the project's head build unless scan_id says otherwise. "
    f"{_ANSWER_NAMES_BUILD}",
    required=["project_id"],
    project_id=_PROJECT_ID,
    scan_id=_SCAN_ID,
    asset_type={
        "type": "string",
        "enum": [t.value for t in CryptoAssetType],
        "description": "Optional filter by asset type",
    },
    primitive={
        "type": "string",
        "enum": [p.value for p in CryptoPrimitive],
        "description": "Optional filter by primitive",
    },
    name_search=_string("Optional substring filter on asset name"),
    skip={"type": "integer", "description": "Number of items to skip (default 0)"},
    limit=_bounded(15, MAX_CRYPTO_ASSET_PAGE, "Max assets"),
)
_tool(
    "get_crypto_asset_details",
    "Get full details of a single cryptographic asset by its ID.",
    required=["project_id", "asset_id"],
    project_id=_PROJECT_ID,
    asset_id=_string("The crypto asset ID"),
)
_tool(
    "get_crypto_summary",
    "Get a summary of cryptographic assets broken down by asset type. Summarises the "
    "project's head build unless scan_id says otherwise. total 0 with cbom_evaluated "
    "false means no CBOM was posted, not that the build has no cryptography. "
    f"{_ANSWER_NAMES_BUILD}",
    required=["project_id"],
    project_id=_PROJECT_ID,
    scan_id=_SCAN_ID,
)
_tool(
    "get_project_crypto_policy",
    "Get the effective cryptographic policy rules for a project: the system rules with "
    "the project's override merged in, one compact row per rule; overridden=true marks a rule "
    "the override changed or added. Pass rule_id for that rule's description, matchers and "
    "references. override_locked=true means a global policy disables project overrides, so "
    "suggest none for this project.",
    required=["project_id"],
    project_id=_PROJECT_ID,
    rule_id=_string("Optional: one rule's full definition instead of the compact list."),
)
_tool(
    "suggest_crypto_policy_override",
    "Advisory: returns the enabled crypto policy rules that match the most findings. Reads "
    "the project's head build unless scan_id says otherwise. Does NOT make any changes — "
    "the caller decides whether to craft a project-scoped override based on the "
    f"suggestions. {_ANSWER_NAMES_BUILD}",
    required=["project_id"],
    project_id=_PROJECT_ID,
    scan_id=_SCAN_ID,
)
_tool(
    "get_crypto_hotspots",
    "List top crypto hotspots for a project, grouped by the given dimension.",
    required=["project_id"],
    project_id=_PROJECT_ID,
    group_by={"type": "string", "enum": list(get_args(GroupBy)), "default": "name"},
    limit=_bounded(20, MAX_CRYPTO_HOTSPOT_PAGE, "Max hotspots"),
)
_tool(
    "get_crypto_trends",
    "Return time-bucketed crypto finding/asset trend data for a project. "
    "Bucket granularity is auto-selected based on the days range.",
    required=["project_id"],
    project_id=_PROJECT_ID,
    metric={"type": "string", "enum": list(get_args(Metric)), "default": "total_crypto_findings"},
    days=_bounded(30, MAX_DAY_WINDOW, "Days to look back"),
)
_tool("get_system_settings", "Get current system-wide configuration.", permissions=_SYSTEM_MANAGE)
_tool("get_system_health", "Get cache health and statistics.", permissions=_SYSTEM_MANAGE)
_tool(
    "generate_pqc_migration_plan",
    "Generate a PQC migration plan for one project.",
    required=["project_id"],
    project_id=_PROJECT_ID,
    limit=_bounded(20, MAX_PQC_PLAN_ITEMS, "Max plan items"),
)
_tool(
    "list_compliance_reports",
    "List recent compliance reports (metadata only).",
    project_id=_ONE_PROJECT,
    framework=_FRAMEWORK,
    limit=_bounded(10, MAX_COMPLIANCE_REPORT_PAGE, "Max reports"),
)
_tool(
    "list_policy_audit_entries",
    "List the change history of the crypto policy or the license policy. License policy history "
    "exists only at project scope; policy_scope=project requires project_id.",
    required=["policy_scope"],
    policy_scope={"type": "string", "enum": ["system", "project"]},
    policy_type={"type": "string", "enum": list(get_args(PolicyType)), "default": "crypto"},
    project_id=_string(),
    limit=_bounded(20, MAX_POLICY_AUDIT_PAGE, "Max entries"),
)
_tool(
    "get_framework_evaluation_summary",
    "Evaluate a compliance framework (crypto standards, the PQC migration plan, the license audit "
    "or the CVE remediation SLA) and return summary counts.",
    required=["scope", "framework"],
    scope={"type": "string", "enum": list(get_args(ScopeName))},
    scope_id=_string(),
    framework=_FRAMEWORK,
)
