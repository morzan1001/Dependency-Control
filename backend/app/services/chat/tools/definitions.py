"""Static tool metadata: TOOL_DEFINITIONS, TOOL_PERMISSIONS, get_tool_definitions().

Pure data — no Mongo / repository imports — so it stays cheap to import and
trivial to introspect from tests / docs tooling.
"""

from typing import Any, Dict, List

from app.core.permissions import Permissions

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    # ── Projects ──
    {
        "type": "function",
        "function": {
            "name": "list_projects",
            "description": (
                "List projects the user can access, with stats (vulnerability counts, "
                "last scan date). Returns max 15 by default. For 'where should I start' "
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
                    "limit": {"type": "integer", "description": "Max projects (default 15, max 50)."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_project_details",
            "description": "Get detailed information about a specific project including members, active analyzers, and configuration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_project_members",
            "description": "Get the list of members and their roles for a project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_project_settings",
            "description": "Get project configuration: retention policy, rescan settings, license policy, active analyzers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["project_id"],
            },
        },
    },
    # ── Scans & Findings ──
    {
        "type": "function",
        "function": {
            "name": "get_scan_history",
            "description": "Get the scan history for a project, showing scan dates, status, and findings summary.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                    "limit": {"type": "integer", "description": "Max number of scans to return (default 10)"},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan_details",
            "description": "Get details of a specific scan: findings summary, stats, branch, commit, status.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "The scan ID"},
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["scan_id", "project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan_findings",
            "description": "Get findings from a specific scan, optionally filtered by severity or type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "The scan ID"},
                    "project_id": {"type": "string", "description": "The project ID"},
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO",
                    },
                    "type": {
                        "type": "string",
                        "description": "Filter by type: vulnerability, secret, sast, malware, license, typosquat",
                    },
                    "limit": {"type": "integer", "description": "Max findings to return (default 50)"},
                },
                "required": ["scan_id", "project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_project_findings",
            "description": "Get the current/latest findings for a project, optionally filtered.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO",
                    },
                    "type": {
                        "type": "string",
                        "description": "Filter by type: vulnerability, secret, sast, malware, license, typosquat",
                    },
                    "limit": {"type": "integer", "description": "Max findings to return (default 50)"},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_vulnerability_details",
            "description": "Get details about a specific vulnerability/finding: CVE info, EPSS score, references, affected component.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "The finding ID"},
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["finding_id", "project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_findings",
            "description": "Search across all findings the user has access to. Use for cross-project queries like 'find all log4j vulnerabilities'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search term (CVE ID, package name, description keyword)",
                    },
                    "severity": {"type": "string", "description": "Filter by severity"},
                    "type": {"type": "string", "description": "Filter by type"},
                    "limit": {"type": "integer", "description": "Max results (default 50)"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings_by_severity",
            "description": "Get a count breakdown of findings grouped by severity for a project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings_by_type",
            "description": "Get findings grouped by type (vulnerability, secret, sast, malware, license, typosquat) for a project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["project_id"],
            },
        },
    },
    # ── Analytics & Trends ──
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
            "description": "Get risk trend data over time: how vulnerability counts changed over days/weeks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Optional: limit to a specific project"},
                    "days": {"type": "integer", "description": "Number of days to look back (default 30)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_dependency_tree",
            "description": "Get the dependency tree of a project showing direct and transitive dependencies.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_hotspots",
            "description": "Get the riskiest dependencies and projects based on vulnerability density and severity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Number of hotspots to return (default 10)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_dependency_details",
            "description": "Get metadata about a dependency: versions, maintainer info, update frequency, known vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dependency_name": {"type": "string", "description": "The dependency/package name (or PURL)"},
                },
                "required": ["dependency_name"],
            },
        },
    },
    # ── Teams ──
    {
        "type": "function",
        "function": {
            "name": "list_teams",
            "description": "List all teams the user belongs to.",
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
            "description": "Get all projects belonging to a specific team.",
            "parameters": {
                "type": "object",
                "properties": {
                    "team_id": {"type": "string", "description": "The team ID"},
                },
                "required": ["team_id"],
            },
        },
    },
    # ── Waivers ──
    {
        "type": "function",
        "function": {
            "name": "get_waiver_status",
            "description": "Check if a finding has been waived (marked as false positive or accepted risk).",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "The finding ID"},
                    "project_id": {"type": "string", "description": "The project ID"},
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
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_global_waivers",
            "description": "List all global waivers that apply across all projects. Requires admin permission.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    # ── Recommendations ──
    {
        "type": "function",
        "function": {
            "name": "get_top_priority_findings",
            "description": (
                "Return the top N most urgent findings across ALL accessible projects, "
                "sorted by severity (CRITICAL first) and EPSS score. Use this when the "
                "user asks 'where should I start?', 'what should I fix first?' or "
                "'which project has the biggest problem?'. Returns a compact list "
                "with finding_id, severity, CVE, affected component and fix_version, "
                "so you can give an actionable answer in a single turn."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "How many findings to return (default 5, max 20).",
                    },
                    "project_id": {
                        "type": "string",
                        "description": "Optional: restrict to a single project.",
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
                "findings by component, picks the smallest upgrade that resolves the most CVEs, "
                "flags direct vs. transitive dependencies and breaking-change risk (major version "
                "bumps). Use this when the user asks 'how do I fix everything', 'build me a plan', "
                "'what's the upgrade path', or similar holistic remediation questions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                    "max_steps": {
                        "type": "integer",
                        "description": "Maximum number of plan steps to return (default 10, max 25).",
                    },
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
                "Return CRITICAL/HIGH findings that already have a known fix_version — "
                "the 'low-hanging fruit' a team can resolve with a simple dependency bump. "
                "Use when the user asks 'what quick wins do I have?', 'what can I fix "
                "easily?' or 'which updates are available?'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Optional: restrict to a single project."},
                    "limit": {"type": "integer", "description": "Max findings to return (default 10, max 25)."},
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
                "Diff two scans of the same project: what is NEW, what got FIXED, "
                "and counts by severity. Use when the user asks 'what changed since "
                "my last deploy?', 'did the last scan introduce new vulns?' or "
                "'which findings did we resolve?'. Without explicit scan ids, "
                "compares the two most recent scans of the project."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID."},
                    "scan_id_a": {"type": "string", "description": "Optional older scan."},
                    "scan_id_b": {"type": "string", "description": "Optional newer scan."},
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
                "Return findings whose CVE is being ACTIVELY EXPLOITED in the wild "
                "(threat-intel exploit_maturity = 'active' or 'weaponized'). These "
                "should always be prioritised over a CVSS-based order. Use when the "
                "user asks 'what is actively exploited?', 'which findings are in KEV?' "
                "or 'show me the stuff with real-world exploits'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Optional: restrict to a single project."},
                    "limit": {"type": "integer", "description": "Max findings (default 10, max 25)."},
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
                "a zero-day in Y?' or during incident scoping. Scans ONLY the latest scan "
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
                "projects. Use when the user mentions a concrete CVE ID. Matches exact "
                "CVE in the nested vulnerabilities list, not free-text."
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
                "EPSS, exploit_maturity, fix versions, external references. Derived "
                "from the most informative occurrence across the user's projects. Use "
                "when the user asks 'tell me about CVE-X' or 'is CVE-X exploitable?'."
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
                "Return findings that have been open for longer than N days — useful "
                "for compliance / SLA tracking. A finding is considered stale when the "
                "same finding_id exists in an older scan (> N days ago) of the same "
                "project AND is still present in the latest scan. Use when the user "
                "asks 'what vulns have we been ignoring?', 'what's old?' or about SLA."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "days_open": {"type": "integer", "description": "Minimum open age in days (default 30)."},
                    "project_id": {"type": "string", "description": "Optional: restrict to one project."},
                    "severity_min": {
                        "type": "string",
                        "description": "Min severity, one of CRITICAL/HIGH/MEDIUM/LOW (default HIGH).",
                    },
                    "limit": {"type": "integer", "description": "Max findings (default 10, max 25)."},
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
                "Return license-compliance findings specifically (type=license). Use "
                "when the user asks about legal / license issues, e.g. 'do we have GPL "
                "in proprietary code?' or 'license violations across the org'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Optional: one project."},
                    "limit": {"type": "integer", "description": "Max findings (default 10, max 25)."},
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
                    "days": {"type": "integer", "description": "Look-ahead window in days (default 30)."},
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
                "Aggregate security posture for a single team: per-team severity "
                "totals plus the three riskiest projects in the team. Use when the "
                "user asks 'how is team X doing?' or 'team-level summary'."
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
                    "days": {"type": "integer", "description": "Threshold in days (default 14)."},
                    "limit": {"type": "integer", "description": "Max projects (default 10, max 50)."},
                },
                "required": [],
            },
        },
    },
    # ── Reachability ──
    {
        "type": "function",
        "function": {
            "name": "get_callgraph",
            "description": "Get the call graph / reachability analysis for a project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
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
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["finding_id", "project_id"],
            },
        },
    },
    # ── Archives ──
    {
        "type": "function",
        "function": {
            "name": "list_archives",
            "description": "List archived scans. Requires archive read permission.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Optional: filter by project"},
                    "limit": {"type": "integer", "description": "Max results (default 20)"},
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
    # ── Webhooks ──
    {
        "type": "function",
        "function": {
            "name": "list_project_webhooks",
            "description": "List webhook configurations for a project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
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
    # ── Crypto / CBOM ──
    {
        "type": "function",
        "function": {
            "name": "list_crypto_assets",
            "description": (
                "List cryptographic assets ingested for a scan. "
                "Supports filtering by asset_type, primitive, and name_search."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                    "scan_id": {"type": "string", "description": "The scan ID"},
                    "asset_type": {"type": "string", "description": "Optional filter by asset type (e.g. 'algorithm')"},
                    "primitive": {"type": "string", "description": "Optional filter by primitive (e.g. 'hash')"},
                    "name_search": {"type": "string", "description": "Optional substring filter on asset name"},
                    "skip": {"type": "integer", "description": "Number of items to skip (default 0)"},
                    "limit": {"type": "integer", "description": "Max results (default 100, max 500)"},
                },
                "required": ["project_id", "scan_id"],
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
                    "project_id": {"type": "string", "description": "The project ID"},
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
            "description": "Get a summary of cryptographic assets for a scan, broken down by asset type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                    "scan_id": {"type": "string", "description": "The scan ID"},
                },
                "required": ["project_id", "scan_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_project_crypto_policy",
            "description": (
                "Get the effective cryptographic policy for a project, "
                "including system-level rules and any project-specific overrides."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
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
                "Advisory: returns the crypto policy rule IDs that produce the most findings "
                "for a scan. Does NOT make any changes — the caller decides whether to craft "
                "a project-scoped override based on the suggestions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                    "scan_id": {"type": "string", "description": "The scan ID"},
                },
                "required": ["project_id", "scan_id"],
            },
        },
    },
    # ── Crypto Analytics ──
    {
        "type": "function",
        "function": {
            "name": "get_crypto_hotspots",
            "description": "List top crypto hotspots for a project, grouped by the given dimension.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "group_by": {
                        "type": "string",
                        "enum": ["name", "primitive", "asset_type", "weakness_tag", "severity"],
                    },
                    "limit": {"type": "integer", "default": 20, "maximum": 100},
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
                    "metric": {
                        "type": "string",
                        "enum": [
                            "total_crypto_findings",
                            "quantum_vulnerable_findings",
                            "weak_algo_findings",
                            "weak_key_findings",
                            "cert_expiring_soon",
                            "cert_expired",
                            "unique_algorithms",
                            "unique_cipher_suites",
                        ],
                    },
                    "days": {"type": "integer", "default": 30, "minimum": 1, "maximum": 365},
                },
                "required": ["project_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan_delta",
            "description": (
                "Compare two scans for a project and return the crypto assets that "
                "were added, removed, or unchanged between them."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "from_scan_id": {"type": "string", "description": "The baseline scan ID"},
                    "to_scan_id": {"type": "string", "description": "The target scan ID"},
                },
                "required": ["project_id", "from_scan_id", "to_scan_id"],
            },
        },
    },
    # ── System (Admin only) ──
    {
        "type": "function",
        "function": {
            "name": "get_system_settings",
            "description": "Get current system-wide configuration. Admin only.",
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
            "description": "Get system health status: database connectivity, worker status, cache stats. Admin only.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    # ── Compliance / PQC-migration (Phase 3) ──
    {
        "type": "function",
        "function": {
            "name": "generate_pqc_migration_plan",
            "description": "Generate a PQC migration plan for one project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 500, "maximum": 2000},
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
                    "framework": {"type": "string"},
                    "limit": {"type": "integer", "default": 10, "maximum": 50},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_policy_audit_entries",
            "description": "List policy audit timeline entries.",
            "parameters": {
                "type": "object",
                "properties": {
                    "policy_scope": {"type": "string", "enum": ["system", "project"]},
                    "project_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 20, "maximum": 100},
                },
                "required": ["policy_scope"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_framework_evaluation_summary",
            "description": "Evaluate a compliance framework and return summary counts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "enum": ["project", "team", "global", "user"]},
                    "scope_id": {"type": "string"},
                    "framework": {
                        "type": "string",
                        "enum": [
                            "nist-sp-800-131a",
                            "bsi-tr-02102",
                            "cnsa-2.0",
                            "fips-140-3",
                            "iso-19790",
                            "pqc-migration-plan",
                        ],
                    },
                },
                "required": ["scope", "framework"],
            },
        },
    },
]


# ── Permission requirements per tool ──

TOOL_PERMISSIONS: Dict[str, List[str]] = {
    # Most tools just need project:read (access is further scoped by build_user_project_query)
    "list_global_waivers": [Permissions.WAIVER_READ_ALL],
    "get_system_settings": [Permissions.SYSTEM_MANAGE],
    "get_system_health": [Permissions.SYSTEM_MANAGE],
    "list_archives": [Permissions.ARCHIVE_READ],
    "get_archive_details": [Permissions.ARCHIVE_READ],
}


def get_tool_definitions() -> List[Dict[str, Any]]:
    """Return all tool definitions in Ollama function-calling format."""
    return TOOL_DEFINITIONS
