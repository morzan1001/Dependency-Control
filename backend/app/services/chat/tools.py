"""Chat tool definitions and execution dispatch.

Each tool wraps an existing repository/service method and enforces
authorization via the requesting user's context.
"""

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.projects import build_user_project_query
from app.core.config import settings
from app.core.metrics import chat_tool_calls_total, chat_tool_duration_seconds
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.findings import FindingRepository
from app.repositories.teams import TeamRepository
from app.repositories.waivers import WaiverRepository

logger = logging.getLogger(__name__)

MAX_TOOL_LIMIT = 200  # Hard cap on LLM-supplied limit arguments to prevent DoS.
MAX_TOOL_RESULT_BYTES = 8_000  # Cap JSON size returned to the LLM per call.

# Threat-intel enrichment values (details.exploit_maturity) that mean the
# vulnerability is actively exploited in the wild — our KEV-equivalent.
KEV_EQUIVALENT_MATURITY = ("active", "weaponized")

# Top-level finding fields surfaced to the LLM. `details` is flattened
# separately to pull CVE IDs / EPSS / fix_version up one level.
_FINDING_TOPLEVEL_FIELDS = (
    "finding_id",
    "severity",
    "type",
    "description",
    "component",
    "version",
    "project_id",
    "scan_id",
    "waived",
    "waiver_reason",
)

# Fields from the `details` subobject that are useful for LLM reasoning.
_FINDING_DETAILS_FIELDS = (
    "fixed_version",
    "epss_score",
    "epss_percentile",
    "exploit_maturity",
    "risk_score",
    "cvss_score",
)


def _clamp_limit(raw: Any, default: int, maximum: int = MAX_TOOL_LIMIT) -> int:
    """Coerce LLM-supplied `limit` to a safe integer, clamped to [1, maximum]."""
    try:
        value = int(raw) if raw is not None else default
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, maximum))


def _clip_value(value: Any) -> Any:
    """Trim long strings/lists that blow up the LLM context."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, str) and len(value) > 400:
        return value[:400] + "…"
    if isinstance(value, list) and len(value) > 5:
        return value[:5] + ["…"]
    return value


def _serialize_finding_for_llm(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact, LLM-friendly projection of a finding document.

    Flattens the `details` subobject and the first CVE from
    `details.vulnerabilities` so the model gets CVE ID + fix + EPSS +
    exploit maturity at the top level without diving into nested structures.
    """
    if not doc:
        return {}
    out: Dict[str, Any] = {}
    for key in _FINDING_TOPLEVEL_FIELDS:
        if doc.get(key) is not None:
            out[key] = _clip_value(doc[key])
    out["id"] = str(doc.get("_id", doc.get("id", "")))

    details = doc.get("details") or {}
    for key in _FINDING_DETAILS_FIELDS:
        if details.get(key) is not None:
            out[key] = _clip_value(details[key])

    vulns = details.get("vulnerabilities") or []
    if vulns:
        # Surface the first CVE as a concrete handle. The model can see there
        # are more via `cve_count`.
        primary = vulns[0]
        if primary.get("id"):
            out["cve"] = primary["id"]
        for k in ("cvss_score", "fixed_version", "epss_score"):
            if primary.get(k) is not None and k not in out:
                out[k] = primary[k]
        refs = primary.get("references") or []
        if refs:
            out["references"] = refs[:3]
        out["cve_count"] = len(vulns)
    return out


def _summary_severity_bucket(severity: Optional[str]) -> str:
    """Map severity label to a bucket key used in our aggregate stats."""
    if not severity:
        return "unknown"
    return severity.lower()


_SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NEGLIGIBLE": 0,
    "INFO": 0,
    "UNKNOWN": 0,
}


def _parse_major(version: Optional[str]) -> Optional[int]:
    """Return the leading numeric component of a version string, or None."""
    if not version or not isinstance(version, str):
        return None
    cleaned = version.lstrip("vV=^~ ").strip()
    head = cleaned.split(".", 1)[0].split("-", 1)[0].split("+", 1)[0]
    try:
        return int(head)
    except (TypeError, ValueError):
        return None


def _compare_versions(a: str, b: str) -> int:
    """Naive tuple comparison of numeric version parts. Returns -1/0/1.
    Falls back to lexicographic when parts are non-numeric — good enough to
    pick the 'largest' fix_version from a candidate list, not a full semver."""
    def parts(v: str) -> List[Any]:
        out: List[Any] = []
        for token in v.lstrip("vV=^~ ").split("."):
            head = token.split("-", 1)[0].split("+", 1)[0]
            try:
                out.append((0, int(head)))
            except (TypeError, ValueError):
                out.append((1, head))
        return out

    pa, pb = parts(a), parts(b)
    for x, y in zip(pa, pb):
        if x < y:
            return -1
        if x > y:
            return 1
    if len(pa) < len(pb):
        return -1
    if len(pa) > len(pb):
        return 1
    return 0


def _breaking_risk(current: Optional[str], target: Optional[str]) -> str:
    """Classify upgrade risk from current→target version."""
    cur_major = _parse_major(current)
    tgt_major = _parse_major(target)
    if cur_major is None or tgt_major is None:
        return "unknown"
    if tgt_major > cur_major:
        return "high"
    if cur_major == 0 and tgt_major == 0:
        # 0.x: any minor bump can break per semver convention.
        return "medium"
    return "low"


def _inject_urls(node: Any) -> None:
    """Walk a tool result tree and add a 'url' field to any dict that has
    enough identifiers to deep-link into the UI. The frontend chat linkifier
    turns `project_name` / `cve` / `component` mentions into links pointing
    at this URL — so the model doesn't need to construct URLs itself.

    Rules, longest-path wins:
      - project_id + scan_id + id (internal finding UUID) → scan details
        with finding drawer auto-opened.
      - project_id + scan_id → scan details.
      - project_id only → project details page.
    """
    base = settings.FRONTEND_BASE_URL.rstrip("/")
    if isinstance(node, list):
        for item in node:
            _inject_urls(item)
        return
    if not isinstance(node, dict):
        return
    pid = node.get("project_id")
    sid = node.get("scan_id")
    fid = node.get("id")
    if isinstance(pid, str) and isinstance(sid, str) and isinstance(fid, str):
        node.setdefault("url", f"{base}/projects/{pid}/scans/{sid}?finding={fid}")
    elif isinstance(pid, str) and isinstance(sid, str):
        node.setdefault("url", f"{base}/projects/{pid}/scans/{sid}")
    elif isinstance(pid, str):
        node.setdefault("url", f"{base}/projects/{pid}")
    for value in node.values():
        _inject_urls(value)


def _truncate_if_too_large(result: Dict[str, Any]) -> Dict[str, Any]:
    """If the JSON encoding exceeds MAX_TOOL_RESULT_BYTES, keep the first
    items of the largest list and replace the rest with a hint. Prevents
    a single tool result from blowing the LLM's context window."""
    import json as _json
    try:
        encoded = _json.dumps(result, default=str)
    except (TypeError, ValueError):
        return result
    if len(encoded) <= MAX_TOOL_RESULT_BYTES:
        return result

    # Find the biggest list in the result and truncate it.
    biggest_key = None
    biggest_len = 0
    for k, v in result.items():
        if isinstance(v, list) and len(v) > biggest_len:
            biggest_key = k
            biggest_len = len(v)
    if biggest_key is None:
        result["_truncated"] = True
        return result

    # Binary-search for the largest prefix that fits
    original = result[biggest_key]
    lo, hi = 0, len(original)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        result[biggest_key] = original[:mid]
        if len(_json.dumps(result, default=str)) <= MAX_TOOL_RESULT_BYTES:
            lo = mid
        else:
            hi = mid - 1
    result[biggest_key] = original[:lo]
    result["_truncated"] = True
    result["_truncation_note"] = (
        f"Result truncated from {biggest_len} to {lo} entries in '{biggest_key}'. "
        f"Call this tool with a smaller limit or a narrower filter for more data."
    )
    return result


# ── Tool metadata ──────────────────────────────────────────────────────────

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
                    "search": {"type": "string", "description": "Optional case-insensitive substring filter on project name."},
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
                    "severity": {"type": "string", "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"},
                    "type": {"type": "string", "description": "Filter by type: vulnerability, secret, sast, malware, license, typosquat"},
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
                    "severity": {"type": "string", "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"},
                    "type": {"type": "string", "description": "Filter by type: vulnerability, secret, sast, malware, license, typosquat"},
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
                    "query": {"type": "string", "description": "Search term (CVE ID, package name, description keyword)"},
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
                    "component_name": {"type": "string", "description": "Package name (substring match, case-insensitive)."},
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
                    "severity_min": {"type": "string", "description": "Min severity, one of CRITICAL/HIGH/MEDIUM/LOW (default HIGH)."},
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


class ChatToolRegistry:
    """Registry that checks which tools a user can access and executes them."""

    def get_available_tool_names(self, user_permissions: List[str]) -> set[str]:
        """Return set of tool names available for given permissions."""
        available = set()
        for tool_def in TOOL_DEFINITIONS:
            name = tool_def["function"]["name"]
            required = TOOL_PERMISSIONS.get(name)
            if required is None:
                # No special permission needed beyond chat:access
                available.add(name)
            elif has_permission(user_permissions, required):
                available.add(name)
        return available

    def get_available_tool_definitions(self, user_permissions: List[str]) -> List[Dict[str, Any]]:
        """Return only the tool definitions the user is authorized to use."""
        available_names = self.get_available_tool_names(user_permissions)
        return [t for t in TOOL_DEFINITIONS if t["function"]["name"] in available_names]

    async def execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user: User,
        db: AsyncIOMotorDatabase,
    ) -> Dict[str, Any]:
        """
        Execute a tool call with user authorization.

        Returns the tool result as a dict.
        """
        # Check tool-level permissions
        required = TOOL_PERMISSIONS.get(tool_name)
        if required and not has_permission(user.permissions, required):
            return {"error": f"You don't have permission to use {tool_name}"}

        start = time.time()
        try:
            result = await self._dispatch(tool_name, arguments, user, db)
            duration = time.time() - start
            chat_tool_calls_total.labels(tool_name=tool_name, status="success").inc()
            chat_tool_duration_seconds.labels(tool_name=tool_name).observe(duration)
            # Inject deep-link URLs for identifiable entities so the model
            # can surface them to the user verbatim.
            if isinstance(result, dict):
                _inject_urls(result)
            # Cap JSON size — large tool dumps (hundreds of projects / thousands
            # of findings) blow the LLM's context budget and make it loop on
            # the same tool trying to re-read data that is already there.
            return _truncate_if_too_large(result) if isinstance(result, dict) else result
        except Exception as e:
            duration = time.time() - start
            chat_tool_calls_total.labels(tool_name=tool_name, status="error").inc()
            chat_tool_duration_seconds.labels(tool_name=tool_name).observe(duration)
            logger.exception(f"Tool {tool_name} failed: {e}")
            return {"error": f"Tool execution failed: {str(e)}"}

    async def _dispatch(
        self,
        tool_name: str,
        args: Dict[str, Any],
        user: User,
        db: AsyncIOMotorDatabase,
    ) -> Dict[str, Any]:
        """Route tool call to the appropriate repository/service method."""
        team_repo = TeamRepository(db)
        project_repo = ProjectRepository(db)
        finding_repo = FindingRepository(db)
        scan_repo = ScanRepository(db)
        waiver_repo = WaiverRepository(db)

        # Build user-scoped project query for data isolation
        user_project_query = await build_user_project_query(user, team_repo)

        # ── Project tools ──
        if tool_name == "list_projects":
            query = {**user_project_query}
            search = args.get("search")
            if search:
                query["name"] = {"$regex": re.escape(search), "$options": "i"}
            limit = _clamp_limit(args.get("limit"), 15, maximum=50)
            cursor = db["projects"].find(query, sort=[("last_scan_at", -1)], limit=limit)
            projects = await cursor.to_list(length=limit)
            return {
                "projects": [_serialize_doc(
                    p, ["_id", "name", "team_id", "stats", "last_scan_at", "created_at"],
                ) for p in projects],
                "count": len(projects),
            }

        if tool_name == "get_project_details":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            return {"project": _serialize_doc(project)}

        if tool_name == "get_project_members":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            return {"members": project.get("members", [])}

        if tool_name == "get_project_settings":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            return {"settings": _serialize_doc(project, ["retention_days", "retention_action", "rescan_enabled", "rescan_interval", "active_analyzers", "license_policy"])}

        # ── Scan tools ──
        if tool_name == "get_scan_history":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            limit = _clamp_limit(args.get("limit"), 10)
            cursor = db["scans"].find({"project_id": args["project_id"]}, sort=[("created_at", -1)], limit=limit)
            scans = await cursor.to_list(length=limit)
            return {"scans": [_serialize_doc(s, ["_id", "status", "branch", "commit_hash", "created_at", "completed_at", "stats"]) for s in scans]}

        if tool_name == "get_scan_details":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            scan = await db["scans"].find_one({"_id": args["scan_id"], "project_id": args["project_id"]})
            if not scan:
                return {"error": "Scan not found"}
            return {"scan": _serialize_doc(scan)}

        if tool_name == "get_scan_findings":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            scan = await db["scans"].find_one({"_id": args["scan_id"], "project_id": args["project_id"]})
            if not scan:
                return {"error": "Scan not found in this project"}
            query: Dict[str, Any] = {"scan_id": args["scan_id"], "project_id": args["project_id"]}
            if args.get("severity"):
                query["severity"] = args["severity"].upper()
            if args.get("type"):
                query["type"] = args["type"]
            limit = _clamp_limit(args.get("limit"), 10, maximum=25)
            cursor = db["findings"].find(query, sort=[("severity", -1)], limit=limit)
            findings = await cursor.to_list(length=limit)
            return {
                "findings": [_serialize_finding_for_llm(f) for f in findings],
                "count": len(findings),
            }

        if tool_name == "get_project_findings":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            latest_scan_id = project.get("latest_scan_id")
            if not latest_scan_id:
                return {"findings": [], "count": 0, "message": "No scans found for this project"}
            query = {"scan_id": latest_scan_id}
            if args.get("severity"):
                query["severity"] = args["severity"].upper()
            if args.get("type"):
                query["type"] = args["type"]
            limit = _clamp_limit(args.get("limit"), 10, maximum=25)
            cursor = db["findings"].find(query, sort=[("severity", -1)], limit=limit)
            findings = await cursor.to_list(length=limit)
            return {
                "findings": [_serialize_finding_for_llm(f) for f in findings],
                "count": len(findings),
                "project_name": project.get("name"),
            }

        if tool_name == "get_vulnerability_details":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            finding = await db["findings"].find_one({"_id": args["finding_id"], "project_id": args["project_id"]})
            if not finding:
                return {"error": "Finding not found"}
            slim = _serialize_finding_for_llm(finding)
            slim["project_name"] = project.get("name", "")
            # Attach full vulnerability list (up to 5) for context
            details = finding.get("details") or {}
            vulns = (details.get("vulnerabilities") or [])[:5]
            if vulns:
                slim["vulnerabilities"] = [{
                    "id": v.get("id"),
                    "severity": v.get("severity"),
                    "cvss_score": v.get("cvss_score"),
                    "fixed_version": v.get("fixed_version"),
                    "epss_score": v.get("epss_score"),
                    "description": _clip_value(v.get("description") or ""),
                    "references": (v.get("references") or [])[:3],
                } for v in vulns]
            return {"finding": slim}

        if tool_name == "search_findings":
            search_query = args["query"]
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            escaped_search_query = re.escape(search_query)
            query = {
                "project_id": {"$in": project_ids},
                "$or": [
                    {"finding_id": {"$regex": escaped_search_query, "$options": "i"}},
                    {"description": {"$regex": escaped_search_query, "$options": "i"}},
                    {"component": {"$regex": escaped_search_query, "$options": "i"}},
                    {"details.vulnerabilities.id": {"$regex": escaped_search_query, "$options": "i"}},
                ],
            }
            if args.get("severity"):
                query["severity"] = args["severity"].upper()
            if args.get("type"):
                query["type"] = args["type"]
            limit = _clamp_limit(args.get("limit"), 10, maximum=25)
            cursor = db["findings"].find(query, limit=limit)
            findings = await cursor.to_list(length=limit)
            names = await self._project_names(db, list({f.get("project_id") for f in findings}))
            out = []
            for f in findings:
                slim = _serialize_finding_for_llm(f)
                slim["project_name"] = names.get(f.get("project_id"), "")
                out.append(slim)
            return {"findings": out, "count": len(out)}

        if tool_name == "get_findings_by_severity":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            latest_scan_id = project.get("latest_scan_id")
            if not latest_scan_id:
                return {"breakdown": {}}
            pipeline = [
                {"$match": {"scan_id": latest_scan_id}},
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            ]
            results = await db["findings"].aggregate(pipeline).to_list(length=10)
            return {"breakdown": {r["_id"]: r["count"] for r in results}}

        if tool_name == "get_findings_by_type":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            latest_scan_id = project.get("latest_scan_id")
            if not latest_scan_id:
                return {"breakdown": {}}
            pipeline = [
                {"$match": {"scan_id": latest_scan_id}},
                {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            ]
            results = await db["findings"].aggregate(pipeline).to_list(length=20)
            return {"breakdown": {r["_id"]: r["count"] for r in results}}

        # ── Analytics tools ──
        if tool_name == "get_analytics_summary":
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            if not project_ids:
                return {"total_projects": 0, "total_findings": 0, "severity_breakdown": {}}
            pipeline = [
                {"$match": {"project_id": {"$in": project_ids}}},
                {"$sort": {"created_at": -1}},
                {"$group": {
                    "_id": "$project_id",
                    "latest_scan_id": {"$first": "$_id"},
                    "stats": {"$first": "$stats"},
                }},
            ]
            latest_scans = await db["scans"].aggregate(pipeline).to_list(length=len(project_ids))
            scan_ids = [s["latest_scan_id"] for s in latest_scans]
            sev_pipeline = [
                {"$match": {"scan_id": {"$in": scan_ids}}},
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            ]
            sev_results = await db["findings"].aggregate(sev_pipeline).to_list(length=10)
            # Top-3 risky projects by critical count so the model can
            # name concrete starting points without another tool call.
            ranked = sorted(
                latest_scans,
                key=lambda s: (s.get("stats") or {}).get("critical", 0),
                reverse=True,
            )[:3]
            project_names_map = await self._project_names(
                db, [s["_id"] for s in ranked]
            )
            top3 = [{
                "project_id": s["_id"],
                "project_name": project_names_map.get(s["_id"], ""),
                "critical": (s.get("stats") or {}).get("critical", 0),
                "high": (s.get("stats") or {}).get("high", 0),
            } for s in ranked]
            return {
                "total_projects": len(project_ids),
                "severity_breakdown": {r["_id"]: r["count"] for r in sev_results},
                "total_findings": sum(r["count"] for r in sev_results),
                "top_risky_projects": top3,
                "hint": (
                    "If the user asked 'where should I start' or 'what is worst', "
                    "name the top_risky_projects directly instead of re-emitting the "
                    "severity breakdown."
                ),
            }

        if tool_name == "get_risk_trends":
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            days = args.get("days", 30)
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            match_query: Dict[str, Any] = {"project_id": {"$in": project_ids}, "created_at": {"$gte": cutoff}}
            if args.get("project_id"):
                # Restrict to the requested project, but only if user has access
                if args["project_id"] not in project_ids:
                    return {"error": "Project not found or access denied"}
                match_query["project_id"] = args["project_id"]
            pipeline = [
                {"$match": match_query},
                {"$sort": {"created_at": 1}},
                {"$project": {"_id": 1, "project_id": 1, "stats": 1, "created_at": 1}},
            ]
            scans = await db["scans"].aggregate(pipeline).to_list(length=500)
            return {"trend_data": [_serialize_doc(s) for s in scans]}

        if tool_name == "get_dependency_tree":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            latest_scan_id = project.get("latest_scan_id")
            if not latest_scan_id:
                return {"dependencies": []}
            cursor = db["dependencies"].find({"scan_id": latest_scan_id}, limit=200)
            deps = await cursor.to_list(length=200)
            return {"dependencies": [_serialize_doc(d) for d in deps]}

        if tool_name == "get_hotspots":
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            limit = _clamp_limit(args.get("limit"), 10)
            pipeline = [
                {"$match": {"project_id": {"$in": project_ids}}},
                {"$sort": {"created_at": -1}},
                {"$group": {"_id": "$project_id", "latest_scan_id": {"$first": "$_id"}, "stats": {"$first": "$stats"}}},
                {"$sort": {"stats.critical": -1}},
                {"$limit": limit},
            ]
            results = await db["scans"].aggregate(pipeline).to_list(length=limit)
            # Enrich with project name so the model can recommend concrete projects.
            project_ids_hit = [r["_id"] for r in results if r.get("_id")]
            names: Dict[str, str] = {}
            async for p in db["projects"].find({"_id": {"$in": project_ids_hit}}, {"name": 1}):
                names[p["_id"]] = p.get("name", "")
            hotspots = []
            for r in results:
                hotspots.append({
                    "project_id": r.get("_id"),
                    "project_name": names.get(r.get("_id"), ""),
                    "latest_scan_id": r.get("latest_scan_id"),
                    "stats": r.get("stats"),
                })
            return {"hotspots": hotspots}

        if tool_name == "get_dependency_details":
            dep = await db["dependency_enrichments"].find_one({"purl": args["dependency_name"]})
            if not dep:
                dep = await db["dependency_enrichments"].find_one(
                    {"name": {"$regex": re.escape(args["dependency_name"]), "$options": "i"}}
                )
            if not dep:
                return {"error": "Dependency not found in enrichment data"}
            return {"dependency": _serialize_doc(dep)}

        # ── Team tools ──
        if tool_name == "list_teams":
            teams = await team_repo.find_by_member(str(user.id))
            return {"teams": [{"id": t.id, "name": t.name, "description": t.description} for t in teams]}

        if tool_name == "get_team_details":
            team = await team_repo.get_by_id(args["team_id"])
            if not team:
                return {"error": "Team not found"}
            if not await team_repo.is_member(args["team_id"], str(user.id)):
                if not has_permission(user.permissions, Permissions.TEAM_READ_ALL):
                    return {"error": "Access denied"}
            return {"team": {"id": team.id, "name": team.name, "description": team.description, "members": [m.model_dump() for m in team.members]}}

        if tool_name == "get_team_projects":
            team = await team_repo.get_by_id(args["team_id"])
            if not team:
                return {"error": "Team not found"}
            if not await team_repo.is_member(args["team_id"], str(user.id)):
                if not has_permission(user.permissions, Permissions.TEAM_READ_ALL):
                    return {"error": "Access denied"}
            query = {**user_project_query, "team_id": args["team_id"]}
            cursor = db["projects"].find(query, limit=50)
            projects = await cursor.to_list(length=50)
            return {"projects": [_serialize_doc(p, ["_id", "name", "stats", "last_scan_at"]) for p in projects]}

        # ── Waiver tools ──
        if tool_name == "get_waiver_status":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            waiver = await db["waivers"].find_one({"finding_id": args["finding_id"], "project_id": args["project_id"]})
            if waiver:
                return {"waived": True, "waiver": _serialize_doc(waiver)}
            global_waiver = await db["waivers"].find_one({"finding_id": args["finding_id"], "global": True})
            if global_waiver:
                return {"waived": True, "waiver": _serialize_doc(global_waiver), "scope": "global"}
            return {"waived": False}

        if tool_name == "list_project_waivers":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            cursor = db["waivers"].find({"project_id": args["project_id"]}, limit=100)
            waivers = await cursor.to_list(length=100)
            return {"waivers": [_serialize_doc(w) for w in waivers]}

        if tool_name == "list_global_waivers":
            cursor = db["waivers"].find({"global": True}, limit=100)
            waivers = await cursor.to_list(length=100)
            return {"waivers": [_serialize_doc(w) for w in waivers]}

        # ── Recommendation tools ──
        if tool_name == "get_top_priority_findings":
            limit = _clamp_limit(args.get("limit"), 5, maximum=20)
            # If a project_id is provided, restrict to that project; else span all
            # projects the user can access.
            match: Dict[str, Any] = {}
            if args.get("project_id"):
                proj = await self._get_authorized_project(
                    args["project_id"], user_project_query, db
                )
                if not proj:
                    return {"error": "Project not found or access denied"}
                latest_scan_id = proj.get("latest_scan_id")
                if not latest_scan_id:
                    return {"findings": [], "message": "No scan data available for this project"}
                match["scan_id"] = latest_scan_id
                match["project_id"] = args["project_id"]
            else:
                # Collect latest scan per authorized project so we only look at
                # current state, not historical findings.
                project_ids = await self._get_authorized_project_ids(user_project_query, db)
                if not project_ids:
                    return {"findings": [], "message": "No accessible projects"}
                latest_scans_pipe = [
                    {"$match": {"project_id": {"$in": project_ids}}},
                    {"$sort": {"created_at": -1}},
                    {"$group": {"_id": "$project_id", "latest_scan_id": {"$first": "$_id"}}},
                ]
                latest = await db["scans"].aggregate(latest_scans_pipe).to_list(length=len(project_ids))
                scan_ids = [row["latest_scan_id"] for row in latest if row.get("latest_scan_id")]
                if not scan_ids:
                    return {"findings": [], "message": "No scans found"}
                match["scan_id"] = {"$in": scan_ids}
            # Prefer CRITICAL, then HIGH — sort severity then EPSS desc for urgency.
            match.setdefault("severity", {"$in": ["CRITICAL", "HIGH"]})
            cursor = db["findings"].find(
                match,
                sort=[("severity", -1), ("epss_score", -1), ("cvss_score", -1)],
                limit=limit,
            )
            findings = await cursor.to_list(length=limit)

            # Enrich with project name so the model can tell the user exactly where to look.
            project_ids_hit = list({f.get("project_id") for f in findings if f.get("project_id")})
            project_names: Dict[str, str] = {}
            if project_ids_hit:
                async for p in db["projects"].find({"_id": {"$in": project_ids_hit}}, {"name": 1}):
                    project_names[p["_id"]] = p.get("name", "")

            trimmed = []
            for f in findings:
                slim = _serialize_finding_for_llm(f)
                pid = f.get("project_id")
                if pid and pid in project_names:
                    slim["project_name"] = project_names[pid]
                trimmed.append(slim)
            return {
                "findings": trimmed,
                "count": len(trimmed),
                "hint": (
                    "Present these to the user as a short ordered list. For each item "
                    "include project_name, CVE, component@version, severity, and the "
                    "fix_version if present. Do not call further tools unless asked."
                ),
            }

        if tool_name == "generate_remediation_plan":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            latest_scan_id = project.get("latest_scan_id")
            if not latest_scan_id:
                return {"plan": [], "message": "No scan data available"}

            max_steps = _clamp_limit(args.get("max_steps"), 10, maximum=25)

            # Pull CRITICAL/HIGH findings for the latest scan. 500 is plenty —
            # plans collapse to a handful of steps after grouping by component.
            cursor = db["findings"].find(
                {
                    "scan_id": latest_scan_id,
                    "severity": {"$in": ["CRITICAL", "HIGH"]},
                    "waived": {"$ne": True},
                },
                limit=500,
            )
            findings = await cursor.to_list(length=500)
            if not findings:
                return {
                    "plan": [],
                    "message": "No unwaived CRITICAL/HIGH findings on the latest scan.",
                }

            # Index direct/transitive info from the dependency snapshot of the
            # latest scan. Keyed by lowercase component name — purl would be
            # more precise but findings don't consistently carry it.
            dep_index: Dict[str, Dict[str, Any]] = {}
            async for dep in db["dependencies"].find(
                {"scan_id": latest_scan_id},
                {"name": 1, "version": 1, "direct": 1, "direct_inferred": 1, "type": 1, "purl": 1},
            ):
                key = (dep.get("name") or "").lower()
                if not key:
                    continue
                # Prefer direct entries when a name appears multiple times
                # (same package pulled in at different versions).
                existing = dep_index.get(key)
                if existing and existing.get("direct") and not dep.get("direct"):
                    continue
                dep_index[key] = dep

            # Group findings by component.
            groups: Dict[str, Dict[str, Any]] = {}
            for f in findings:
                comp = (
                    f.get("component")
                    or f.get("component_name")
                    or f.get("package")
                    or f.get("package_name")
                )
                if not comp:
                    continue
                key = comp.lower()
                g = groups.setdefault(
                    key,
                    {
                        "component": comp,
                        "current_version": f.get("component_version")
                        or f.get("package_version")
                        or f.get("version"),
                        "findings": [],
                        "fix_candidates": [],
                    },
                )
                g["findings"].append(f)
                # Collect any fix_version hint from this finding.
                for fv in (f.get("fixed_versions") or []):
                    if isinstance(fv, str) and fv:
                        g["fix_candidates"].append(fv)
                single = f.get("fix_version")
                if isinstance(single, str) and single:
                    g["fix_candidates"].append(single)

            # Build plan steps.
            steps: List[Dict[str, Any]] = []
            for key, g in groups.items():
                # Pick the largest fix version that appears across this component's
                # findings — that's the one that resolves the most CVEs at once.
                target: Optional[str] = None
                for cand in g["fix_candidates"]:
                    if target is None or _compare_versions(cand, target) > 0:
                        target = cand

                dep_meta = dep_index.get(key) or {}
                is_direct = bool(dep_meta.get("direct")) and not dep_meta.get("direct_inferred")
                current = g["current_version"] or dep_meta.get("version")

                resolved = [
                    {
                        "finding_id": str(f.get("_id", f.get("id", ""))),
                        "cve_id": f.get("cve_id"),
                        "severity": f.get("severity"),
                    }
                    for f in g["findings"]
                ]
                max_sev = max(
                    (_SEVERITY_RANK.get(f.get("severity") or "", 0) for f in g["findings"]),
                    default=0,
                )
                max_sev_label = next(
                    (k for k, v in _SEVERITY_RANK.items() if v == max_sev),
                    "UNKNOWN",
                )
                critical_count = sum(1 for f in g["findings"] if f.get("severity") == "CRITICAL")

                risk = _breaking_risk(current, target) if target else "unknown"

                steps.append(
                    {
                        "component": g["component"],
                        "ecosystem": dep_meta.get("type"),
                        "current_version": current,
                        "target_version": target,
                        "is_direct": is_direct,
                        "resolves_findings": resolved[:10],
                        "resolves_count": len(resolved),
                        "critical_count": critical_count,
                        "max_severity": max_sev_label,
                        "breaking_change_risk": risk,
                        "has_fix": target is not None,
                    }
                )

            # Order: fixable direct deps with low risk first (quick wins),
            # then critical count desc, then total findings desc.
            risk_order = {"low": 0, "medium": 1, "high": 2, "unknown": 3}

            def sort_key(s: Dict[str, Any]) -> tuple:
                return (
                    0 if s["has_fix"] else 1,
                    0 if s["is_direct"] else 1,
                    risk_order.get(s["breaking_change_risk"], 3),
                    -s["critical_count"],
                    -s["resolves_count"],
                )

            steps.sort(key=sort_key)
            steps = steps[:max_steps]
            for i, step in enumerate(steps, start=1):
                step["step"] = i

            summary = {
                "total_steps": len(steps),
                "findings_resolved": sum(s["resolves_count"] for s in steps),
                "critical_resolved": sum(s["critical_count"] for s in steps),
                "steps_without_fix": sum(1 for s in steps if not s["has_fix"]),
                "breaking_changes": sum(
                    1 for s in steps if s["breaking_change_risk"] == "high"
                ),
            }

            return {
                "project_id": args["project_id"],
                "project_name": project.get("name"),
                "plan": steps,
                "summary": summary,
                "hint": (
                    "Present this as a numbered Markdown plan. For each step show "
                    "component current_version → target_version, severity badge, "
                    "# CVEs resolved, direct/transitive, and breaking_change_risk. "
                    "Group visually into 'Quick wins' (low risk) and 'Major upgrades' "
                    "(high risk) if both exist. Mention steps_without_fix separately "
                    "as items that need manual investigation (no upstream patch yet)."
                ),
            }

        # ── New focused / analytics tools ──
        if tool_name == "get_auto_fixable_findings":
            latest = await self._latest_scan_ids_for_user(user_project_query, args.get("project_id"), db)
            if not latest:
                return {"findings": [], "message": "No scan data available"}
            limit = _clamp_limit(args.get("limit"), 10, maximum=25)
            cursor = db["findings"].find(
                {
                    "scan_id": {"$in": list(latest.values())},
                    "severity": {"$in": ["CRITICAL", "HIGH"]},
                    "details.fixed_version": {"$exists": True, "$ne": None},
                    "waived": {"$ne": True},
                },
                sort=[("severity", -1), ("details.epss_score", -1)],
                limit=limit,
            )
            rows = await cursor.to_list(length=limit)
            names = await self._project_names(db, list({f.get("project_id") for f in rows}))
            out = []
            for f in rows:
                slim = _serialize_finding_for_llm(f)
                slim["project_name"] = names.get(f.get("project_id"), "")
                out.append(slim)
            return {
                "findings": out,
                "count": len(out),
                "hint": "These already have a fix_version — recommend the upgrade directly.",
            }

        if tool_name == "suggest_waiver_for_finding":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            finding = await db["findings"].find_one(
                {"finding_id": args["finding_id"], "project_id": args["project_id"]}
            )
            if not finding:
                return {"error": "Finding not found"}
            details = finding.get("details") or {}
            sev = (finding.get("severity") or "").upper()
            maturity = details.get("exploit_maturity")
            epss = details.get("epss_score")
            fix = details.get("fixed_version")

            reasons = []
            if maturity in KEV_EQUIVALENT_MATURITY:
                return {
                    "suggested_reason": (
                        "NOT RECOMMENDED TO WAIVE. This vulnerability has exploit_maturity="
                        f"'{maturity}' — it is actively exploited in the wild. Patch rather than waive."
                    ),
                    "suggested_expiry_days": 0,
                    "recommend_waive": False,
                }
            if fix:
                reasons.append(f"a fix is available (upgrade to {fix})")
            if isinstance(epss, (int, float)) and epss < 0.01:
                reasons.append(f"real-world exploit likelihood is low (EPSS={epss:.4f})")
            if sev in ("LOW", "NEGLIGIBLE", "INFO"):
                reasons.append(f"severity is {sev}")
            suggested_reason = (
                "Accepted risk: " + "; ".join(reasons) + "."
                if reasons
                else "Accepted risk: insert justification here. No strong automatic signal found."
            )
            expiry_days = 180 if (fix or (isinstance(epss, (int, float)) and epss < 0.01)) else 90
            return {
                "suggested_reason": suggested_reason,
                "suggested_expiry_days": expiry_days,
                "recommend_waive": True,
                "signals": {
                    "severity": sev,
                    "exploit_maturity": maturity,
                    "epss_score": epss,
                    "has_fix_version": bool(fix),
                },
                "hint": (
                    "Show these signals to the user and let them edit the suggested reason "
                    "before creating the waiver. This tool does NOT create the waiver."
                ),
            }

        if tool_name == "compare_scans":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            scan_a_id = args.get("scan_id_a")
            scan_b_id = args.get("scan_id_b")
            if not scan_a_id or not scan_b_id:
                # Default: the two most recent scans
                recent = await db["scans"].find(
                    {"project_id": args["project_id"]},
                    sort=[("created_at", -1)],
                    limit=2,
                ).to_list(length=2)
                if len(recent) < 2:
                    return {"error": "Need at least two scans to compare"}
                scan_b_id = recent[0]["_id"]
                scan_a_id = recent[1]["_id"]
            scan_a = await db["scans"].find_one({"_id": scan_a_id, "project_id": args["project_id"]})
            scan_b = await db["scans"].find_one({"_id": scan_b_id, "project_id": args["project_id"]})
            if not scan_a or not scan_b:
                return {"error": "Scan not found in this project"}
            # Pull (finding_id, severity) pairs for each side
            async def _ids(scan_id: str) -> Dict[str, str]:
                items: Dict[str, str] = {}
                async for f in db["findings"].find(
                    {"scan_id": scan_id},
                    {"finding_id": 1, "severity": 1},
                ):
                    if f.get("finding_id"):
                        items[f["finding_id"]] = f.get("severity", "UNKNOWN")
                return items

            a_ids, b_ids = await _ids(scan_a_id), await _ids(scan_b_id)
            new_keys = set(b_ids) - set(a_ids)
            fixed_keys = set(a_ids) - set(b_ids)
            unchanged_keys = set(a_ids) & set(b_ids)

            def _sev_bucket(keys: set[str], sev_source: Dict[str, str]) -> Dict[str, int]:
                bucket: Dict[str, int] = {}
                for k in keys:
                    sev = sev_source.get(k, "UNKNOWN")
                    bucket[sev] = bucket.get(sev, 0) + 1
                return bucket

            # Return a small sample of each side so the LLM has concrete handles
            def _sample(keys: set[str]) -> List[str]:
                return sorted(keys)[:10]

            return {
                "scan_a": {
                    "id": scan_a_id,
                    "created_at": scan_a.get("created_at").isoformat() if hasattr(scan_a.get("created_at"), "isoformat") else scan_a.get("created_at"),
                    "branch": scan_a.get("branch"),
                },
                "scan_b": {
                    "id": scan_b_id,
                    "created_at": scan_b.get("created_at").isoformat() if hasattr(scan_b.get("created_at"), "isoformat") else scan_b.get("created_at"),
                    "branch": scan_b.get("branch"),
                },
                "new_findings_count": len(new_keys),
                "new_findings_by_severity": _sev_bucket(new_keys, b_ids),
                "new_findings_sample": _sample(new_keys),
                "fixed_findings_count": len(fixed_keys),
                "fixed_findings_by_severity": _sev_bucket(fixed_keys, a_ids),
                "fixed_findings_sample": _sample(fixed_keys),
                "unchanged_count": len(unchanged_keys),
            }

        if tool_name == "get_kev_findings":
            latest = await self._latest_scan_ids_for_user(user_project_query, args.get("project_id"), db)
            if not latest:
                return {"findings": [], "message": "No scan data available"}
            limit = _clamp_limit(args.get("limit"), 10, maximum=25)
            cursor = db["findings"].find(
                {
                    "scan_id": {"$in": list(latest.values())},
                    "details.exploit_maturity": {"$in": list(KEV_EQUIVALENT_MATURITY)},
                    "waived": {"$ne": True},
                },
                sort=[("severity", -1), ("details.epss_score", -1)],
                limit=limit,
            )
            rows = await cursor.to_list(length=limit)
            names = await self._project_names(db, list({f.get("project_id") for f in rows}))
            out = []
            for f in rows:
                slim = _serialize_finding_for_llm(f)
                slim["project_name"] = names.get(f.get("project_id"), "")
                out.append(slim)
            return {
                "findings": out,
                "count": len(out),
                "hint": (
                    "All of these have real-world exploits. Prioritise above plain CVSS-only "
                    "critical findings."
                ),
            }

        if tool_name == "find_component_usage":
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            if not project_ids:
                return {"matches": [], "message": "No accessible projects"}
            latest = await self._latest_scan_ids_for_user(user_project_query, None, db)
            latest_scan_ids = list(latest.values())
            dep_query: Dict[str, Any] = {
                "name": {"$regex": re.escape(args["component_name"]), "$options": "i"},
                "scan_id": {"$in": latest_scan_ids},
            }
            if args.get("version"):
                dep_query["version"] = args["version"]
            cursor = db["dependencies"].find(
                dep_query,
                {"name": 1, "version": 1, "project_id": 1, "direct": 1, "purl": 1, "license": 1},
                limit=100,
            )
            rows = await cursor.to_list(length=100)
            names = await self._project_names(db, list({r.get("project_id") for r in rows}))
            matches = []
            for r in rows:
                matches.append({
                    "project_id": r.get("project_id"),
                    "project_name": names.get(r.get("project_id"), ""),
                    "component": r.get("name"),
                    "version": r.get("version"),
                    "direct_dependency": bool(r.get("direct")),
                    "purl": r.get("purl"),
                    "license": r.get("license"),
                })
            return {"matches": matches, "count": len(matches)}

        if tool_name == "get_findings_by_cve":
            cve = args["cve_id"].strip().upper()
            latest = await self._latest_scan_ids_for_user(user_project_query, None, db)
            if not latest:
                return {"findings": [], "message": "No scan data available"}
            cursor = db["findings"].find(
                {
                    "scan_id": {"$in": list(latest.values())},
                    "details.vulnerabilities.id": cve,
                },
                limit=25,
            )
            rows = await cursor.to_list(length=25)
            names = await self._project_names(db, list({f.get("project_id") for f in rows}))
            by_project: Dict[str, Dict[str, Any]] = {}
            for f in rows:
                pid = f.get("project_id")
                slot = by_project.setdefault(pid, {
                    "project_id": pid,
                    "project_name": names.get(pid, ""),
                    "findings": [],
                })
                slot["findings"].append(_serialize_finding_for_llm(f))
            return {
                "cve_id": cve,
                "affected_projects": list(by_project.values()),
                "project_count": len(by_project),
                "total_occurrences": len(rows),
            }

        if tool_name == "get_cve_details":
            cve = args["cve_id"].strip().upper()
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            if not project_ids:
                return {"error": "No accessible projects to source CVE data from"}
            finding = await db["findings"].find_one(
                {
                    "project_id": {"$in": project_ids},
                    "details.vulnerabilities.id": cve,
                }
            )
            if not finding:
                return {"error": f"{cve} not found in any of your projects' scan data"}
            details = finding.get("details") or {}
            vulns = details.get("vulnerabilities") or []
            vuln = next((v for v in vulns if (v.get("id") or "").upper() == cve), None) or {}
            return {
                "cve_id": cve,
                "severity": vuln.get("severity") or finding.get("severity"),
                "cvss_score": vuln.get("cvss_score") or details.get("cvss_score"),
                "cvss_vector": vuln.get("cvss_vector"),
                "epss_score": vuln.get("epss_score") or details.get("epss_score"),
                "epss_percentile": details.get("epss_percentile"),
                "exploit_maturity": details.get("exploit_maturity"),
                "actively_exploited": details.get("exploit_maturity") in KEV_EQUIVALENT_MATURITY,
                "description": _clip_value(vuln.get("description") or ""),
                "fixed_version": vuln.get("fixed_version") or details.get("fixed_version"),
                "references": (vuln.get("references") or [])[:5],
                "affected_component": f"{finding.get('component','')}@{finding.get('version','')}",
                "source_scanners": vuln.get("scanners"),
            }

        if tool_name == "get_stale_findings":
            from datetime import datetime as _dt, timezone as _tz, timedelta as _td
            days = _clamp_limit(args.get("days_open"), 30, maximum=365)
            limit = _clamp_limit(args.get("limit"), 10, maximum=25)
            sev_min = (args.get("severity_min") or "HIGH").upper()
            allowed_sev = [s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                           if _SEVERITY_RANK.get(s, 0) >= _SEVERITY_RANK.get(sev_min, 3)]
            latest = await self._latest_scan_ids_for_user(user_project_query, args.get("project_id"), db)
            if not latest:
                return {"findings": [], "message": "No scan data available"}
            cutoff = _dt.now(_tz.utc) - _td(days=days)
            project_ids = list(latest.keys())
            # Step 1: collect (project_id, finding_id) pairs that existed before cutoff
            old_keys: set = set()
            async for f in db["findings"].find(
                {"project_id": {"$in": project_ids}, "created_at": {"$lt": cutoff}},
                {"project_id": 1, "finding_id": 1},
            ):
                if f.get("project_id") and f.get("finding_id"):
                    old_keys.add((f["project_id"], f["finding_id"]))
            if not old_keys:
                return {"findings": [], "message": f"No findings older than {days} days"}
            # Step 2: look at findings in latest scans, keep those also in old set
            cursor = db["findings"].find(
                {"scan_id": {"$in": list(latest.values())}, "severity": {"$in": allowed_sev}},
                sort=[("severity", -1), ("details.epss_score", -1)],
            )
            stale = []
            async for f in cursor:
                key = (f.get("project_id"), f.get("finding_id"))
                if key in old_keys:
                    stale.append(f)
                    if len(stale) >= limit:
                        break
            names = await self._project_names(db, list({f.get("project_id") for f in stale}))
            out = []
            for f in stale:
                slim = _serialize_finding_for_llm(f)
                slim["project_name"] = names.get(f.get("project_id"), "")
                out.append(slim)
            return {
                "findings": out,
                "count": len(out),
                "days_open_threshold": days,
                "hint": (
                    "These findings have lingered for more than the threshold. "
                    "Suggest either fixing, waiving with justification, or escalating."
                ),
            }

        if tool_name == "get_license_violations":
            latest = await self._latest_scan_ids_for_user(user_project_query, args.get("project_id"), db)
            if not latest:
                return {"findings": [], "message": "No scan data available"}
            limit = _clamp_limit(args.get("limit"), 10, maximum=25)
            cursor = db["findings"].find(
                {"scan_id": {"$in": list(latest.values())}, "type": "license"},
                sort=[("severity", -1)],
                limit=limit,
            )
            rows = await cursor.to_list(length=limit)
            names = await self._project_names(db, list({f.get("project_id") for f in rows}))
            out = []
            for f in rows:
                slim = _serialize_finding_for_llm(f)
                slim["project_name"] = names.get(f.get("project_id"), "")
                out.append(slim)
            return {"findings": out, "count": len(out)}

        if tool_name == "get_expiring_waivers":
            from datetime import datetime as _dt, timezone as _tz, timedelta as _td
            days = _clamp_limit(args.get("days"), 30, maximum=365)
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            now = _dt.now(_tz.utc)
            cutoff = now + _td(days=days)
            cursor = db["waivers"].find(
                {
                    "project_id": {"$in": project_ids},
                    "expiration_date": {"$gte": now, "$lte": cutoff},
                    "status": {"$ne": "expired"},
                },
                sort=[("expiration_date", 1)],
                limit=25,
            )
            rows = await cursor.to_list(length=25)
            names = await self._project_names(db, list({r.get("project_id") for r in rows}))
            out = []
            for w in rows:
                expires = w.get("expiration_date")
                out.append({
                    "project_id": w.get("project_id"),
                    "project_name": names.get(w.get("project_id"), ""),
                    "finding_id": w.get("finding_id"),
                    "vulnerability_id": w.get("vulnerability_id"),
                    "reason": _clip_value(w.get("reason") or ""),
                    "expires_at": expires.isoformat() if hasattr(expires, "isoformat") else expires,
                    "package": f"{w.get('package_name','')}@{w.get('package_version','')}",
                })
            return {"waivers": out, "count": len(out), "window_days": days}

        if tool_name == "get_team_risk_overview":
            team = await team_repo.get_by_id(args["team_id"])
            if not team:
                return {"error": "Team not found"}
            if not await team_repo.is_member(args["team_id"], str(user.id)):
                if not has_permission(user.permissions, Permissions.TEAM_READ_ALL):
                    return {"error": "Access denied"}
            cursor = db["projects"].find({"team_id": args["team_id"]}, {"_id": 1, "name": 1, "stats": 1, "last_scan_at": 1})
            projects = await cursor.to_list(length=500)
            totals: Dict[str, int] = {}
            risky = []
            for p in projects:
                stats = p.get("stats") or {}
                for sev in ("critical", "high", "medium", "low"):
                    totals[sev] = totals.get(sev, 0) + int(stats.get(sev, 0) or 0)
                risky.append((
                    int(stats.get("critical", 0) or 0),
                    int(stats.get("high", 0) or 0),
                    p.get("_id"),
                    p.get("name", ""),
                ))
            risky.sort(reverse=True)
            top3 = [
                {"project_id": pid, "project_name": name, "critical": c, "high": h}
                for c, h, pid, name in risky[:3]
            ]
            return {
                "team_id": args["team_id"],
                "team_name": getattr(team, "name", ""),
                "project_count": len(projects),
                "severity_totals": totals,
                "top_risky_projects": top3,
            }

        if tool_name == "get_projects_without_recent_scan":
            from datetime import datetime as _dt, timezone as _tz, timedelta as _td
            days = _clamp_limit(args.get("days"), 14, maximum=365)
            limit = _clamp_limit(args.get("limit"), 10, maximum=50)
            cutoff = _dt.now(_tz.utc) - _td(days=days)
            query = {
                "$or": [
                    {"last_scan_at": {"$lt": cutoff}},
                    {"last_scan_at": None},
                    {"last_scan_at": {"$exists": False}},
                ],
            }
            if user_project_query:
                query = {"$and": [query, user_project_query]}
            cursor = db["projects"].find(query, {"_id": 1, "name": 1, "last_scan_at": 1}, limit=limit)
            rows = await cursor.to_list(length=limit)
            out = []
            for p in rows:
                last = p.get("last_scan_at")
                out.append({
                    "project_id": p.get("_id"),
                    "project_name": p.get("name", ""),
                    "last_scan_at": last.isoformat() if hasattr(last, "isoformat") else last,
                    "never_scanned": last is None,
                })
            return {"projects": out, "count": len(out), "threshold_days": days}

        # ── Reachability tools ──
        if tool_name in ("get_callgraph", "check_reachability"):
            project = await self._get_authorized_project(args.get("project_id", ""), user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            if tool_name == "get_callgraph":
                doc = await db["callgraph"].find_one({"project_id": args["project_id"]})
                return {"callgraph": _serialize_doc(doc) if doc else None}
            if tool_name == "check_reachability":
                finding = await db["findings"].find_one({"_id": args["finding_id"], "project_id": args["project_id"]})
                if not finding:
                    return {"error": "Finding not found"}
                return {"reachable": finding.get("reachable", "unknown"), "finding_id": args["finding_id"]}

        # ── Archive tools ──
        if tool_name == "list_archives":
            query = {}
            if args.get("project_id"):
                project = await self._get_authorized_project(args["project_id"], user_project_query, db)
                if not project:
                    return {"error": "Project not found or access denied"}
                query["project_id"] = args["project_id"]
            elif not has_permission(user.permissions, Permissions.ARCHIVE_READ_ALL):
                project_ids = await self._get_authorized_project_ids(user_project_query, db)
                query["project_id"] = {"$in": project_ids}
            limit = _clamp_limit(args.get("limit"), 20)
            cursor = db["archive_metadata"].find(query, sort=[("archived_at", -1)], limit=limit)
            archives = await cursor.to_list(length=limit)
            return {"archives": [_serialize_doc(a) for a in archives]}

        if tool_name == "get_archive_details":
            archive = await db["archive_metadata"].find_one({"_id": args["archive_id"]})
            if not archive:
                return {"error": "Archive not found or access denied"}
            if not has_permission(user.permissions, Permissions.ARCHIVE_READ_ALL):
                project = await self._get_authorized_project(archive.get("project_id", ""), user_project_query, db)
                if not project:
                    return {"error": "Archive not found or access denied"}
            return {"archive": _serialize_doc(archive)}

        # ── Webhook tools ──
        if tool_name == "list_project_webhooks":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            cursor = db["webhooks"].find({"project_id": args["project_id"]}, limit=20)
            webhooks = await cursor.to_list(length=20)
            return {"webhooks": [_serialize_doc(w) for w in webhooks]}

        if tool_name == "get_webhook_deliveries":
            webhook = await db["webhooks"].find_one({"_id": args["webhook_id"]})
            if not webhook:
                return {"error": "Webhook not found"}
            project = await self._get_authorized_project(webhook.get("project_id", ""), user_project_query, db)
            if not project:
                return {"error": "Access denied"}
            cursor = db["webhook_deliveries"].find({"webhook_id": args["webhook_id"]}, sort=[("timestamp", -1)], limit=20)
            deliveries = await cursor.to_list(length=20)
            return {"deliveries": [_serialize_doc(d) for d in deliveries]}

        # ── System tools ──
        if tool_name == "get_system_settings":
            doc = await db["system_settings"].find_one({"_id": "current"})
            return {"settings": _serialize_doc(doc) if doc else {}}

        if tool_name == "get_system_health":
            from app.core.cache import cache_service
            cache_health = await cache_service.health_check()
            return {"database": "connected", "cache": cache_health}

        return {"error": f"Unknown tool: {tool_name}"}

    async def _get_authorized_project(
        self, project_id: str, user_project_query: Dict[str, Any], db: AsyncIOMotorDatabase
    ) -> Optional[Dict[str, Any]]:
        """Fetch a project only if user has access.

        Contract: `user_project_query` must be the result of
        build_user_project_query(user, team_repo). That helper is the single
        source of truth for authorization — it returns {} only for users with
        PROJECT_READ_ALL permission. Any caller bypassing that helper MUST
        enforce equivalent checks; otherwise an empty dict here is a security
        bypass. DO NOT refactor this to compute the query inline without
        auditing every caller.

        NOTE: Using $and to compose the project ID and user-scoped query avoids
        the silent authorization bypass that would occur if user_project_query
        ever contained an `_id` key and we used a naive .update() merge.
        """
        if not user_project_query:
            # Empty query => build_user_project_query confirmed PROJECT_READ_ALL.
            return await db["projects"].find_one({"_id": project_id})
        return await db["projects"].find_one({
            "$and": [{"_id": project_id}, user_project_query]
        })

    async def _get_authorized_project_ids(
        self, user_project_query: Dict[str, Any], db: AsyncIOMotorDatabase
    ) -> List[str]:
        """Get all project IDs user has access to."""
        cursor = db["projects"].find(user_project_query, projection={"_id": 1})
        projects = await cursor.to_list(length=1000)
        return [p["_id"] for p in projects]

    async def _latest_scan_ids_for_user(
        self,
        user_project_query: Dict[str, Any],
        restrict_to_project_id: Optional[str],
        db: AsyncIOMotorDatabase,
    ) -> Dict[str, str]:
        """Return a {project_id: latest_scan_id} mapping limited to authorised projects.

        If `restrict_to_project_id` is given, the map is validated against the user's
        scope and only that single entry is returned (empty dict on access denial).
        """
        if restrict_to_project_id:
            proj = await self._get_authorized_project(
                restrict_to_project_id, user_project_query, db
            )
            if not proj or not proj.get("latest_scan_id"):
                return {}
            return {restrict_to_project_id: proj["latest_scan_id"]}

        project_ids = await self._get_authorized_project_ids(user_project_query, db)
        if not project_ids:
            return {}
        pipeline = [
            {"$match": {"project_id": {"$in": project_ids}}},
            {"$sort": {"created_at": -1}},
            {"$group": {"_id": "$project_id", "latest_scan_id": {"$first": "$_id"}}},
        ]
        rows = await db["scans"].aggregate(pipeline).to_list(length=len(project_ids))
        return {row["_id"]: row["latest_scan_id"] for row in rows if row.get("latest_scan_id")}

    @staticmethod
    async def _project_names(
        db: AsyncIOMotorDatabase, project_ids: List[str]
    ) -> Dict[str, str]:
        """Bulk lookup project name by id, skipping None/empty inputs."""
        cleaned = [pid for pid in project_ids if pid]
        if not cleaned:
            return {}
        names: Dict[str, str] = {}
        async for p in db["projects"].find({"_id": {"$in": cleaned}}, {"name": 1}):
            names[p["_id"]] = p.get("name", "")
        return names


def _serialize_doc(doc: Optional[Dict[str, Any]], fields: Optional[List[str]] = None) -> Dict[str, Any]:
    """Serialize a MongoDB doc for LLM consumption. Converts _id and datetime."""
    if doc is None:
        return {}
    if fields:
        result = {}
        for f in fields:
            if f == "_id":
                result["id"] = str(doc.get("_id", ""))
            elif f in doc:
                val = doc[f]
                if hasattr(val, "isoformat"):
                    result[f] = val.isoformat()
                else:
                    result[f] = val
        return result
    # Full serialization
    result = {}
    for k, v in doc.items():
        key = "id" if k == "_id" else k
        if hasattr(v, "isoformat"):
            result[key] = v.isoformat()
        elif isinstance(v, bytes):
            continue
        else:
            result[key] = v
    return result
