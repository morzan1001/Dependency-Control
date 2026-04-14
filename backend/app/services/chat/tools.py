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
from app.core.metrics import chat_tool_calls_total, chat_tool_duration_seconds
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.findings import FindingRepository
from app.repositories.teams import TeamRepository
from app.repositories.waivers import WaiverRepository

logger = logging.getLogger(__name__)


# ── Tool metadata ──────────────────────────────────────────────────────────

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    # ── Projects ──
    {
        "type": "function",
        "function": {
            "name": "list_projects",
            "description": "List all projects the user has access to, with their stats (vulnerability counts, last scan date).",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Optional search term to filter project names"},
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
            "description": "Get a cross-project risk summary: total vulnerabilities by severity, top risky projects, overall risk score.",
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
            "name": "get_dependency_impact",
            "description": "Find which projects use a specific dependency. Useful for impact analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dependency_name": {"type": "string", "description": "The dependency/package name"},
                    "version": {"type": "string", "description": "Optional: specific version"},
                },
                "required": ["dependency_name"],
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
            "name": "get_recommendations",
            "description": "Get remediation recommendations for a project: what to fix first, suggested updates, priority order.",
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
            "name": "get_update_suggestions",
            "description": "Get available updates for vulnerable dependencies in a project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "The project ID"},
                },
                "required": ["project_id"],
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
            return result
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
            cursor = db["projects"].find(query, sort=[("last_scan_at", -1)], limit=50)
            projects = await cursor.to_list(length=50)
            return {"projects": [_serialize_doc(p, ["_id", "name", "team_id", "stats", "last_scan_at", "created_at"]) for p in projects]}

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
            limit = args.get("limit", 10)
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
            limit = args.get("limit", 50)
            cursor = db["findings"].find(query, sort=[("severity", -1)], limit=limit)
            findings = await cursor.to_list(length=limit)
            return {"findings": [_serialize_doc(f) for f in findings], "count": len(findings)}

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
            limit = args.get("limit", 50)
            cursor = db["findings"].find(query, sort=[("severity", -1)], limit=limit)
            findings = await cursor.to_list(length=limit)
            return {"findings": [_serialize_doc(f) for f in findings], "count": len(findings)}

        if tool_name == "get_vulnerability_details":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            finding = await db["findings"].find_one({"_id": args["finding_id"], "project_id": args["project_id"]})
            if not finding:
                return {"error": "Finding not found"}
            return {"finding": _serialize_doc(finding)}

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
                ],
            }
            if args.get("severity"):
                query["severity"] = args["severity"].upper()
            if args.get("type"):
                query["type"] = args["type"]
            limit = args.get("limit", 50)
            cursor = db["findings"].find(query, limit=limit)
            findings = await cursor.to_list(length=limit)
            return {"findings": [_serialize_doc(f) for f in findings], "count": len(findings)}

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
            pipeline = [
                {"$match": {"project_id": {"$in": project_ids}}},
                {"$sort": {"created_at": -1}},
                {"$group": {"_id": "$project_id", "latest_scan_id": {"$first": "$_id"}}},
            ]
            latest_scans = await db["scans"].aggregate(pipeline).to_list(length=1000)
            scan_ids = [s["latest_scan_id"] for s in latest_scans]
            sev_pipeline = [
                {"$match": {"scan_id": {"$in": scan_ids}}},
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            ]
            sev_results = await db["findings"].aggregate(sev_pipeline).to_list(length=10)
            return {
                "total_projects": len(project_ids),
                "severity_breakdown": {r["_id"]: r["count"] for r in sev_results},
                "total_findings": sum(r["count"] for r in sev_results),
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

        if tool_name in ("get_dependency_tree", "get_dependency_impact", "get_hotspots", "get_dependency_details"):
            # These delegate to analytics/enrichment services
            # Stub: return data from the dependencies collection
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

            if tool_name == "get_dependency_impact":
                project_ids = await self._get_authorized_project_ids(user_project_query, db)
                cursor = db["dependencies"].find(
                    {"name": {"$regex": re.escape(args["dependency_name"]), "$options": "i"}, "project_id": {"$in": project_ids}},
                    limit=100,
                )
                deps = await cursor.to_list(length=100)
                return {"affected_projects": [_serialize_doc(d, ["_id", "project_id", "name", "version"]) for d in deps]}

            if tool_name == "get_hotspots":
                project_ids = await self._get_authorized_project_ids(user_project_query, db)
                limit = args.get("limit", 10)
                pipeline = [
                    {"$match": {"project_id": {"$in": project_ids}}},
                    {"$sort": {"created_at": -1}},
                    {"$group": {"_id": "$project_id", "latest_scan_id": {"$first": "$_id"}, "stats": {"$first": "$stats"}}},
                    {"$sort": {"stats.critical": -1}},
                    {"$limit": limit},
                ]
                results = await db["scans"].aggregate(pipeline).to_list(length=limit)
                return {"hotspots": [_serialize_doc(r) for r in results]}

            if tool_name == "get_dependency_details":
                dep = await db["dependency_enrichments"].find_one({"purl": args["dependency_name"]})
                if not dep:
                    dep = await db["dependency_enrichments"].find_one({"name": {"$regex": re.escape(args["dependency_name"]), "$options": "i"}})
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
        if tool_name in ("get_recommendations", "get_update_suggestions"):
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": "Project not found or access denied"}
            # Get latest findings and derive recommendations
            latest_scan_id = project.get("latest_scan_id")
            if not latest_scan_id:
                return {"recommendations": [], "message": "No scan data available"}
            cursor = db["findings"].find(
                {"scan_id": latest_scan_id, "severity": {"$in": ["CRITICAL", "HIGH"]}},
                sort=[("severity", -1)],
                limit=20,
            )
            findings = await cursor.to_list(length=20)
            return {"recommendations": [_serialize_doc(f) for f in findings], "message": "Prioritized by severity. Fix CRITICAL first, then HIGH."}

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
            limit = args.get("limit", 20)
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
        """Fetch a project only if user has access."""
        query = {"_id": project_id}
        if user_project_query:
            query.update(user_project_query)
        return await db["projects"].find_one(query)

    async def _get_authorized_project_ids(
        self, user_project_query: Dict[str, Any], db: AsyncIOMotorDatabase
    ) -> List[str]:
        """Get all project IDs user has access to."""
        cursor = db["projects"].find(user_project_query, projection={"_id": 1})
        projects = await cursor.to_list(length=1000)
        return [p["_id"] for p in projects]


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
