"""Central dispatcher for chat tool calls with permission checks and result post-processing."""

import logging
import re
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.projects import build_user_project_query
from app.core.constants import (
    MAX_COMPLIANCE_REPORT_PAGE,
    MAX_CRYPTO_ASSET_PAGE,
    MAX_CRYPTO_HOTSPOT_PAGE,
    MAX_POLICY_AUDIT_PAGE,
    MAX_PQC_PLAN_ITEMS,
)
from app.core.metrics import chat_tool_calls_total, chat_tool_duration_seconds
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.scans import ScanRepository
from app.repositories.teams import TeamRepository
from app.services.aggregation.components import artifact_segment, build_component_index, lookup_component
from app.services.analytics.crypto_delta import compute_crypto_delta_envelope
from app.services.analytics.findings_delta import FINDING_IDENTITY_PROJECTION, compute_findings_delta
from app.services.analyzers.purl_utils import canonical_purl
from app.services.reachability_enrichment import reachability_display_tier

from ._helpers import (
    _SEVERITY_RANK,
    KEV_EQUIVALENT_MATURITY,
    MAX_DAY_WINDOW,
    MAX_FINDING_ROWS,
    MAX_PLAN_STEPS,
    MAX_SUMMARY_ROWS,
    _breaking_risk,
    _clamp_limit,
    _clip_value,
    _compare_versions,
    _ensure_list,
    _inject_urls,
    _serialize_doc,
    _serialize_finding_for_llm,
    _truncate_if_too_large,
    _waiver_is_active,
    begin_limit_ledger,
    bounded_read,
    bounded_read_note,
    clamped_limit_note,
    staleness_identities,
)
from .crypto_tools import (
    generate_pqc_migration_plan,
    get_crypto_asset_details,
    get_crypto_hotspots,
    get_crypto_summary,
    get_crypto_trends,
    get_framework_evaluation_summary,
    get_project_crypto_policy,
    list_compliance_reports,
    list_crypto_assets,
    list_policy_audit_entries,
    suggest_crypto_policy_override,
)
from .definitions import TOOL_DEFINITIONS, TOOL_PERMISSIONS

logger = logging.getLogger(__name__)

_ERR_PROJECT_NOT_FOUND = "Project not found or access denied"
_ERR_SCAN_NOT_FOUND_IN_PROJECT = "Scan not found in this project"
_ERR_FINDING_NOT_FOUND = "Finding not found"
_ERR_TEAM_NOT_FOUND = "Team not found"
_ERR_ACCESS_DENIED = "Access denied"
_ERR_NO_SCAN_DATA = "No scan data available"
_ERR_NEED_TWO_SCANS = "Need at least two builds on the head branch to compare"
_FIELD_VULN_ID = "details.vulnerabilities.id"
_FIELD_EPSS_SCORE = "details.epss_score"

# Everything an answer needs to name the build it describes.
_BUILD_PROJECTION = {"branch": 1, "commit_hash": 1, "created_at": 1, "status": 1}

# Candidate set pulled per severity tier and ranked in-process on the numeric tiebreakers, which
# `severity` being a string cannot express in a server-side sort. Bounding a tier rather than the
# whole match is what keeps the highest severities in the sample.
_FINDING_RANK_FETCH_CAP = 1000

# Highest severity first; the trailing clause catches values outside the known set so no finding
# is unreachable to the walk.
_SEVERITY_TIERS: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INFO", "UNKNOWN")

_RANKING_SAMPLED = (
    "State this caveat in your answer: the {tier} tier holds {total} findings and only "
    "{cap} were read, so these are {tier} findings but not necessarily the worst {tier} ones. "
    "Narrow the question — a single project, or a finding type — for an exact answer."
)

# How many projects the summary names as the worst; projects tie on their critical count often
# enough that the id has to break it, or the same estate ranks differently request to request.
_TOP_RISKY = 3

# Read ceilings for the tools that answer from a whole collection rather than from a ranked page.
# Every answer built on one of these carries the population it was cut from.
_DEPENDENCY_TREE_READ = 200
_TEAM_PROJECT_READ = 50
_WAIVER_READ = 100
_WEBHOOK_READ = 20
_WEBHOOK_DELIVERY_READ = 20
_TREND_SCAN_READ = 500
_REMEDIATION_FINDING_READ = 500
_COMPONENT_USAGE_READ = 100
_CVE_OCCURRENCE_READ = 25
_EXPIRING_WAIVER_READ = 25
_TEAM_RISK_PROJECT_READ = 500
_AUTHORIZED_PROJECT_READ = 1000

# A callgraph's `imports`/`calls` arrays run into the megabytes; the tool answers from the
# aggregates only.
_CALLGRAPH_SUMMARY_PROJECTION = {
    "_id": 1,
    "module_usage": 1,
    "analyzed_modules": 1,
    "language": 1,
    "created_at": 1,
    "scan_id": 1,
    "pipeline_id": 1,
    "total_imports": 1,
    "total_calls": 1,
}


def _scan_lookup_error(requested_scan_id: str | None) -> str:
    """A named scan the project does not have is a bad argument; an absent one means nothing built yet."""
    return _ERR_SCAN_NOT_FOUND_IN_PROJECT if requested_scan_id else _ERR_NO_SCAN_DATA


def _stat(stats: dict[str, Any] | None, severity: str) -> int:
    """A severity count off a scan's stats block; a scan carrying none counts as zero."""
    try:
        return int((stats or {}).get(severity, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _row_project_id(row: dict[str, Any]) -> str:
    """A row's project id as a name-lookup key; the empty string for a row carrying none."""
    return str(row.get("project_id") or "")


def _finding_detail_number(finding: dict[str, Any], field: str) -> float:
    """Return a numeric `details.<field>` for tiebreak sorting; missing/non-numeric -> -1.0."""
    details = finding.get("details") or {}
    value = details.get(field)
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else -1.0


# How a dependency's directness was established. `direct` alone cannot express it: an
# inferred-direct package is direct, but ranks below a declared one when ordering fixes.
_DIRECT_CONFIDENCE_RANK = {"declared": 0, "inferred": 1, "transitive": 2}


def _direct_confidence(dep: dict[str, Any]) -> str:
    if not dep.get("direct"):
        return "transitive"
    return "inferred" if dep.get("direct_inferred") else "declared"


def _rank_findings(findings: list[dict[str, Any]]) -> None:
    """Sort findings in place by severity rank desc, then details.epss_score and details.cvss_score desc."""
    findings.sort(
        key=lambda f: (
            _SEVERITY_RANK.get((f.get("severity") or "").upper(), 0),
            _finding_detail_number(f, "epss_score"),
            _finding_detail_number(f, "cvss_score"),
        ),
        reverse=True,
    )


def _severity_tiers(requested: Any) -> list[Any]:
    """The `severity` clauses to walk, worst first. A caller's own clause narrows the walk instead
    of being overwritten, so a tool asking for CRITICAL still only ever sees CRITICAL."""
    if isinstance(requested, str):
        return [requested.upper()]
    if isinstance(requested, dict) and isinstance(requested.get("$in"), list):
        wanted = [str(s).upper() for s in requested["$in"]]
        known = [s for s in _SEVERITY_TIERS if s in wanted]
        return known + [s for s in wanted if s not in _SEVERITY_TIERS]
    return [*_SEVERITY_TIERS, {"$nin": list(_SEVERITY_TIERS)}]


async def _ranked_findings(
    db: AsyncIOMotorDatabase,
    query: dict[str, Any],
    limit: int,
    *,
    keep: Callable[[dict[str, Any]], bool] | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """The `limit` worst findings for `query`, filled one severity tier at a time so a scan whose
    natural order opens with thousands of LOW findings cannot hide its criticals. Also returns the
    caveat to relay when a tier that fed the answer held more candidates than the cap."""
    out: list[dict[str, Any]] = []
    note: str | None = None
    for tier in _severity_tiers(query.get("severity")):
        if len(out) >= limit:
            break
        tier_query = {**query, "severity": tier}
        cursor = db["findings"].find(tier_query, limit=_FINDING_RANK_FETCH_CAP)
        candidates = await cursor.to_list(length=_FINDING_RANK_FETCH_CAP)
        if not candidates:
            continue
        if note is None and len(candidates) >= _FINDING_RANK_FETCH_CAP:
            note = _RANKING_SAMPLED.format(
                tier=tier if isinstance(tier, str) else "lowest-severity",
                total=await db["findings"].count_documents(tier_query),
                cap=_FINDING_RANK_FETCH_CAP,
            )
        _rank_findings(candidates)
        for finding in candidates:
            if keep is not None and not keep(finding):
                continue
            out.append(finding)
            if len(out) >= limit:
                break
    return out, note


class ChatToolRegistry:
    def get_available_tool_names(self, user_permissions: list[str]) -> set[str]:
        available = set()
        for tool_def in TOOL_DEFINITIONS:
            name = tool_def["function"]["name"]
            required = TOOL_PERMISSIONS.get(name)
            if required is None or has_permission(user_permissions, required):
                available.add(name)
        return available

    def get_available_tool_definitions(self, user_permissions: list[str]) -> list[dict[str, Any]]:
        available_names = self.get_available_tool_names(user_permissions)
        return [t for t in TOOL_DEFINITIONS if t["function"]["name"] in available_names]

    async def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        user: User,
        db: AsyncIOMotorDatabase,
    ) -> dict[str, Any]:
        required = TOOL_PERMISSIONS.get(tool_name)
        if required and not has_permission(user.permissions, required):
            return {"error": f"You don't have permission to use {tool_name}"}

        start = time.time()
        begin_limit_ledger()
        try:
            result = await self._dispatch(tool_name, arguments, user, db)
            duration = time.time() - start
            chat_tool_calls_total.labels(tool_name=tool_name, status="success").inc()
            chat_tool_duration_seconds.labels(tool_name=tool_name).observe(duration)
            if isinstance(result, dict):
                _inject_urls(result)
                note = clamped_limit_note()
                if note:
                    result["_limit_clamped"] = True
                    result["_limit_clamp_note"] = note
                saturated = bounded_read_note()
                if saturated:
                    result["_bounded_read"] = True
                    result["_bounded_read_note"] = saturated
            # Cap JSON size so a large dump can't blow the LLM's context budget.
            return _truncate_if_too_large(result) if isinstance(result, dict) else result
        except Exception as e:
            duration = time.time() - start
            chat_tool_calls_total.labels(tool_name=tool_name, status="error").inc()
            chat_tool_duration_seconds.labels(tool_name=tool_name).observe(duration)
            logger.exception(f"Tool {tool_name} failed: {e}")
            return {"error": f"Tool execution failed: {e!s}"}

    async def _dispatch(
        self,
        tool_name: str,
        args: dict[str, Any],
        user: User,
        db: AsyncIOMotorDatabase,
    ) -> dict[str, Any]:
        team_repo = TeamRepository(db)
        user_project_query = await build_user_project_query(user, team_repo)

        if tool_name == "list_projects":
            query = {**user_project_query}
            search = args.get("search")
            if search:
                query["name"] = {"$regex": re.escape(search), "$options": "i"}
            limit = _clamp_limit(args.get("limit"), 15, maximum=MAX_SUMMARY_ROWS)
            cursor = db["projects"].find(query, sort=[("last_scan_at", -1)], limit=limit)
            projects = await cursor.to_list(length=limit)
            return {
                "projects": [
                    _serialize_doc(
                        p,
                        ["_id", "name", "team_id", "stats", "last_scan_at", "created_at"],
                    )
                    for p in projects
                ],
                "count": len(projects),
            }

        if tool_name == "get_project_details":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            return {"project": _serialize_doc(project)}

        if tool_name == "get_project_members":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            return {"members": project.get("members", [])}

        if tool_name == "get_project_settings":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            return {
                "settings": _serialize_doc(
                    project,
                    [
                        "retention_days",
                        "retention_action",
                        "rescan_enabled",
                        "rescan_interval",
                        "active_analyzers",
                        "license_policy",
                    ],
                )
            }

        if tool_name == "get_scan_history":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            limit = _clamp_limit(args.get("limit"), 10, maximum=MAX_SUMMARY_ROWS)
            # Newest-first across every branch and status, so the first row is a queued run on a
            # branch nobody ships as often as it is the build the project stands on.
            cursor = db["scans"].find({"project_id": args["project_id"]}, sort=[("created_at", -1)], limit=limit)
            scans = await cursor.to_list(length=limit)
            head_scan_id = await self._head_scan_id(project, db)
            return {
                "scans": [
                    {
                        **_serialize_doc(
                            s, ["_id", "status", "branch", "commit_hash", "created_at", "completed_at", "stats"]
                        ),
                        "is_head": s["_id"] == head_scan_id,
                    }
                    for s in scans
                ],
                "head_scan_id": head_scan_id,
                "hint": (
                    "head_scan_id is the build that represents this project. Rows are ordered by "
                    "time across all branches and statuses, so the first one often is not it."
                ),
            }

        if tool_name == "get_scan_details":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            answer_scan = await self._scan_under_answer(project, args.get("scan_id"), db)
            if not answer_scan:
                return {"error": _scan_lookup_error(args.get("scan_id"))}
            scan_id, build = answer_scan
            scan = await db["scans"].find_one({"_id": scan_id, "project_id": args["project_id"]})
            return {"scan": {**_serialize_doc(scan), "is_head": build["is_head"]}}

        if tool_name == "get_scan_findings":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            answer_scan = await self._scan_under_answer(project, args.get("scan_id"), db)
            if not answer_scan:
                return {"error": _scan_lookup_error(args.get("scan_id"))}
            scan_id, build = answer_scan
            query = {"scan_id": scan_id, "project_id": args["project_id"]}
            if args.get("severity"):
                query["severity"] = args["severity"].upper()
            if args.get("type"):
                query["type"] = args["type"]
            limit = _clamp_limit(args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
            findings, ranking_note = await _ranked_findings(db, query, limit)
            return {
                "findings": [_serialize_finding_for_llm(f) for f in findings],
                "count": len(findings),
                "scan": build,
                **({"ranking_note": ranking_note} if ranking_note else {}),
            }

        if tool_name == "get_project_findings":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            head_scan_id = await self._head_scan_id(project, db)
            if not head_scan_id:
                return {"findings": [], "count": 0, "message": "No scans found for this project"}
            query = {"scan_id": head_scan_id}
            if args.get("severity"):
                query["severity"] = args["severity"].upper()
            if args.get("type"):
                query["type"] = args["type"]
            limit = _clamp_limit(args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
            findings, ranking_note = await _ranked_findings(db, query, limit)
            return {
                "findings": [_serialize_finding_for_llm(f) for f in findings],
                "count": len(findings),
                "project_name": project.get("name"),
                **({"ranking_note": ranking_note} if ranking_note else {}),
            }

        if tool_name == "get_vulnerability_details":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            finding = await db["findings"].find_one({"_id": args["finding_id"], "project_id": args["project_id"]})
            if not finding:
                return {"error": _ERR_FINDING_NOT_FOUND}
            slim = _serialize_finding_for_llm(finding)
            slim["project_name"] = project.get("name", "")
            details = finding.get("details") or {}
            vulns = (details.get("vulnerabilities") or [])[:5]
            if vulns:
                slim["vulnerabilities"] = [
                    {
                        "id": v.get("id"),
                        "severity": v.get("severity"),
                        "cvss_score": v.get("cvss_score"),
                        "fixed_version": v.get("fixed_version"),
                        "epss_score": v.get("epss_score"),
                        "description": _clip_value(v.get("description") or ""),
                        "references": (v.get("references") or [])[:3],
                    }
                    for v in vulns
                ]
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
                    {_FIELD_VULN_ID: {"$regex": escaped_search_query, "$options": "i"}},
                ],
            }
            if args.get("severity"):
                query["severity"] = args["severity"].upper()
            if args.get("type"):
                query["type"] = args["type"]
            limit = _clamp_limit(args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
            cursor = db["findings"].find(query, limit=limit)
            findings = await cursor.to_list(length=limit)
            names = await self._project_names(db, list({_row_project_id(f) for f in findings}))
            out = []
            for f in findings:
                slim = _serialize_finding_for_llm(f)
                slim["project_name"] = names.get(_row_project_id(f), "")
                out.append(slim)
            return {"findings": out, "count": len(out)}

        if tool_name == "get_findings_by_severity":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            head_scan_id = await self._head_scan_id(project, db)
            if not head_scan_id:
                return {"breakdown": {}}
            pipeline: list[dict[str, Any]] = [
                {"$match": {"scan_id": head_scan_id}},
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            ]
            results = await db["findings"].aggregate(pipeline).to_list(length=10)
            return {"breakdown": {r["_id"]: r["count"] for r in results}}

        if tool_name == "get_findings_by_type":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            head_scan_id = await self._head_scan_id(project, db)
            if not head_scan_id:
                return {"breakdown": {}}
            pipeline = [
                {"$match": {"scan_id": head_scan_id}},
                {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            ]
            results = await db["findings"].aggregate(pipeline).to_list(length=20)
            return {"breakdown": {r["_id"]: r["count"] for r in results}}

        if tool_name == "get_analytics_summary":
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            if not project_ids:
                return {"total_projects": 0, "total_findings": 0, "severity_breakdown": {}}
            head = await self._latest_scan_ids_for_user(user_project_query, None, db)
            stats_by_project = await self._head_scan_stats(db, head)
            sev_pipeline: list[dict[str, Any]] = [
                {"$match": {"scan_id": {"$in": list(head.values())}}},
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            ]
            sev_results = await db["findings"].aggregate(sev_pipeline).to_list(length=10)
            ranked = sorted(head, key=lambda pid: (-_stat(stats_by_project.get(pid), "critical"), pid))[:_TOP_RISKY]
            project_names_map = await self._project_names(db, ranked)
            top3 = [
                {
                    "project_id": pid,
                    "project_name": project_names_map.get(pid, ""),
                    "critical": _stat(stats_by_project.get(pid), "critical"),
                    "high": _stat(stats_by_project.get(pid), "high"),
                }
                for pid in ranked
            ]
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
            match_query: dict[str, Any] = {"project_id": {"$in": project_ids}, "created_at": {"$gte": cutoff}}
            if args.get("project_id"):
                if args["project_id"] not in project_ids:
                    return {"error": _ERR_PROJECT_NOT_FOUND}
                match_query["project_id"] = args["project_id"]
            scans, scans_total = await bounded_read(
                db["scans"],
                match_query,
                subject="scans in the window",
                limit=_TREND_SCAN_READ,
                sort=[("created_at", 1)],
                projection={"_id": 1, "project_id": 1, "stats": 1, "created_at": 1},
            )
            return {
                "trend_data": [_serialize_doc(s) for s in scans],
                "trend_data_total": scans_total,
            }

        if tool_name == "get_dependency_tree":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            head_scan_id = await self._head_scan_id(project, db)
            if not head_scan_id:
                return {"dependencies": []}
            deps, deps_total = await bounded_read(
                db["dependencies"],
                {"scan_id": head_scan_id},
                subject="dependencies",
                limit=_DEPENDENCY_TREE_READ,
            )
            return {
                "dependencies": [_serialize_doc(d) for d in deps],
                "dependencies_total": deps_total,
            }

        if tool_name == "get_hotspots":
            limit = _clamp_limit(args.get("limit"), 10, maximum=MAX_SUMMARY_ROWS)
            head = await self._latest_scan_ids_for_user(user_project_query, None, db)
            stats_by_project = await self._head_scan_stats(db, head)
            ranked = sorted(head, key=lambda pid: (-_stat(stats_by_project.get(pid), "critical"), pid))[:limit]
            names = await self._project_names(db, ranked)
            hotspots = [
                {
                    "project_id": pid,
                    "project_name": names.get(pid, ""),
                    "latest_scan_id": head[pid],
                    "stats": stats_by_project.get(pid),
                }
                for pid in ranked
            ]
            return {"hotspots": hotspots}

        if tool_name == "get_dependency_details":
            dep = await db["dependency_enrichments"].find_one({"purl": canonical_purl(args["dependency_name"])})
            if not dep:
                dep = await db["dependency_enrichments"].find_one(
                    {"name": {"$regex": re.escape(args["dependency_name"]), "$options": "i"}}
                )
            if not dep:
                return {"error": "Dependency not found in enrichment data"}
            return {"dependency": _serialize_doc(dep)}

        if tool_name == "list_teams":
            teams = await team_repo.find_by_member(str(user.id))
            return {"teams": [{"id": t.id, "name": t.name, "description": t.description} for t in teams]}

        if tool_name == "get_team_details":
            team = await team_repo.get_by_id(args["team_id"])
            if not team:
                return {"error": _ERR_TEAM_NOT_FOUND}
            if not await team_repo.is_member(args["team_id"], str(user.id)) and not has_permission(
                user.permissions, Permissions.TEAM_READ_ALL
            ):
                return {"error": _ERR_ACCESS_DENIED}
            return {
                "team": {
                    "id": team.id,
                    "name": team.name,
                    "description": team.description,
                    "members": [m.model_dump() for m in team.members],
                }
            }

        if tool_name == "get_team_projects":
            team = await team_repo.get_by_id(args["team_id"])
            if not team:
                return {"error": _ERR_TEAM_NOT_FOUND}
            if not await team_repo.is_member(args["team_id"], str(user.id)) and not has_permission(
                user.permissions, Permissions.TEAM_READ_ALL
            ):
                return {"error": _ERR_ACCESS_DENIED}
            query = {**user_project_query, "team_id": args["team_id"]}
            projects, projects_total = await bounded_read(
                db["projects"], query, subject="team projects", limit=_TEAM_PROJECT_READ
            )
            return {
                "projects": [_serialize_doc(p, ["_id", "name", "stats", "last_scan_at"]) for p in projects],
                "projects_total": projects_total,
            }

        if tool_name == "get_waiver_status":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            head_scan_id = await self._head_scan_id(project, db)
            finding = None
            if head_scan_id:
                finding = await db["findings"].find_one(
                    {"scan_id": head_scan_id, "finding_id": args["finding_id"]},
                    {"waived": 1, "waiver_reason": 1, "waiver_lapsed": 1, "lapsed_waiver_id": 1},
                )
            if finding is not None:
                resp: dict[str, Any] = {"waived": bool(finding.get("waived"))}
                if finding.get("waiver_reason"):
                    resp["waiver_reason"] = finding["waiver_reason"]
                if finding.get("waiver_lapsed"):
                    resp["lapsed"] = True
                    resp["lapsed_waiver_id"] = finding.get("lapsed_waiver_id")
                return resp
            # No finding doc for this id in the latest scan: an existing waiver row
            # suppresses nothing, so report it as present-but-not-suppressing.
            now = datetime.now(timezone.utc)
            waiver = await db["waivers"].find_one(
                {"finding_id": args["finding_id"], "project_id": args["project_id"]}
            ) or await db["waivers"].find_one({"finding_id": args["finding_id"], "project_id": None})
            if not waiver:
                return {"waived": False}
            if _waiver_is_active(waiver, now):
                return {
                    "waived": False,
                    "waiver_present": True,
                    "suppressing": False,
                    "reason": "no matching finding in the latest scan — finding fixed/moved or waiver dormant",
                    "waiver": _serialize_doc(waiver),
                }
            return {"waived": False, "expired_waiver": _serialize_doc(waiver)}

        if tool_name == "list_project_waivers":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            now = datetime.now(timezone.utc)
            waivers, waivers_total = await bounded_read(
                db["waivers"], {"project_id": args["project_id"]}, subject="waivers", limit=_WAIVER_READ
            )
            return {
                "waivers": [{**_serialize_doc(w), "is_active": _waiver_is_active(w, now)} for w in waivers],
                "waivers_total": waivers_total,
            }

        if tool_name == "list_global_waivers":
            now = datetime.now(timezone.utc)
            waivers, waivers_total = await bounded_read(
                db["waivers"], {"project_id": None}, subject="global waivers", limit=_WAIVER_READ
            )
            return {
                "waivers": [{**_serialize_doc(w), "is_active": _waiver_is_active(w, now)} for w in waivers],
                "waivers_total": waivers_total,
            }

        if tool_name == "get_top_priority_findings":
            limit = _clamp_limit(args.get("limit"), 5, maximum=MAX_FINDING_ROWS)
            match: dict[str, Any] = {}
            if args.get("project_id"):
                proj = await self._get_authorized_project(args["project_id"], user_project_query, db)
                if not proj:
                    return {"error": _ERR_PROJECT_NOT_FOUND}
                head_scan_id = await self._head_scan_id(proj, db)
                if not head_scan_id:
                    return {"findings": [], "message": "No scan data available for this project"}
                match["scan_id"] = head_scan_id
                match["project_id"] = args["project_id"]
            else:
                # Each project's head, to look at current state rather than history.
                project_ids = await self._get_authorized_project_ids(user_project_query, db)
                if not project_ids:
                    return {"findings": [], "message": "No accessible projects"}
                head = await self._latest_scan_ids_for_user(user_project_query, None, db)
                if not head:
                    return {"findings": [], "message": "No scans found"}
                match["scan_id"] = {"$in": list(head.values())}
            match.setdefault("severity", {"$in": ["CRITICAL", "HIGH"]})
            findings, ranking_note = await _ranked_findings(db, match, limit)

            project_ids_hit = list({f.get("project_id") for f in findings if f.get("project_id")})
            project_names: dict[str, str] = {}
            if project_ids_hit:
                async for p in db["projects"].find({"_id": {"$in": project_ids_hit}}, {"name": 1}):
                    project_names[p["_id"]] = p.get("name", "")

            trimmed = []
            for f in findings:
                slim = _serialize_finding_for_llm(f)
                pid = _row_project_id(f)
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
                **({"ranking_note": ranking_note} if ranking_note else {}),
            }

        if tool_name == "generate_remediation_plan":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            head_scan_id = await self._head_scan_id(project, db)
            if not head_scan_id:
                return {"plan": [], "message": _ERR_NO_SCAN_DATA}

            max_steps = _clamp_limit(args.get("max_steps"), 10, maximum=MAX_PLAN_STEPS)

            findings, findings_total = await bounded_read(
                db["findings"],
                {
                    "scan_id": head_scan_id,
                    "severity": {"$in": ["CRITICAL", "HIGH"]},
                    "waived": {"$ne": True},
                },
                subject="unwaived CRITICAL/HIGH findings",
                limit=_REMEDIATION_FINDING_READ,
            )
            if not findings:
                return {
                    "plan": [],
                    "message": "No unwaived CRITICAL/HIGH findings on the latest scan.",
                }

            # Keyed by lowercase component name — purl would be more precise
            # but findings don't consistently carry it.
            dep_index: dict[str, dict[str, Any]] = {}
            async for dep in db["dependencies"].find(
                {"scan_id": head_scan_id},
                {"name": 1, "version": 1, "direct": 1, "direct_inferred": 1, "type": 1, "purl": 1},
            ):
                key = (dep.get("name") or "").lower()
                if not key:
                    continue
                # Prefer direct entries when same package appears at multiple versions.
                existing = dep_index.get(key)
                if existing and existing.get("direct") and not dep.get("direct"):
                    continue
                dep_index[key] = dep
            # Findings carry the qualified component while the inventory keeps the bare name.
            dep_index = build_component_index(dep_index)

            groups: dict[str, dict[str, Any]] = {}
            for f in findings:
                comp = f.get("component")
                if not comp:
                    continue
                key = comp.lower()
                g = groups.setdefault(
                    key,
                    {
                        "component": comp,
                        "current_version": f.get("version"),
                        "findings": [],
                        "fix_candidates": [],
                    },
                )
                g["findings"].append(f)
                details = f.get("details") or {}
                entries = details.get("vulnerabilities") or []
                for fv in (details.get("fixed_version"), *(v.get("fixed_version") for v in entries)):
                    if isinstance(fv, str) and fv:
                        # Writers emit comma-joined fix lists ("1.2.6, 2.0.1"); compare single versions.
                        g["fix_candidates"].extend(part for part in (c.strip() for c in fv.split(",")) if part)

            steps: list[dict[str, Any]] = []
            for key, g in groups.items():
                # Pick largest fix version — resolves the most CVEs at once.
                target: str | None = None
                for cand in g["fix_candidates"]:
                    if target is None or _compare_versions(cand, target) > 0:
                        target = cand

                dep_meta = lookup_component(dep_index, key) or {}
                confidence = _direct_confidence(dep_meta)
                current = g["current_version"] or dep_meta.get("version")

                resolved = []
                for f in g["findings"]:
                    entries = (f.get("details") or {}).get("vulnerabilities") or []
                    if not entries:
                        # Non-vulnerability findings carry no CVE list; label with the finding id.
                        entries = [{}]
                    for v in entries:
                        resolved.append(
                            {
                                "finding_id": f.get("finding_id"),
                                "cve_id": v.get("resolved_cve") or v.get("id") or f.get("finding_id"),
                                "severity": v.get("severity") or f.get("severity"),
                            }
                        )
                max_sev = max(
                    (_SEVERITY_RANK.get(f.get("severity") or "", 0) for f in g["findings"]),
                    default=0,
                )
                max_sev_label = next(
                    (k for k, v in _SEVERITY_RANK.items() if v == max_sev),
                    "UNKNOWN",
                )
                critical_count = sum(1 for r in resolved if r["severity"] == "CRITICAL")

                risk = _breaking_risk(current, target) if target else "unknown"

                steps.append(
                    {
                        "component": g["component"],
                        "ecosystem": dep_meta.get("type"),
                        "current_version": current,
                        "target_version": target,
                        "is_direct": confidence != "transitive",
                        "direct_confidence": confidence,
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

            def sort_key(s: dict[str, Any]) -> tuple:
                return (
                    0 if s["has_fix"] else 1,
                    # A graph-declared direct dependency still outranks an inferred one.
                    _DIRECT_CONFIDENCE_RANK[s["direct_confidence"]],
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
                "cves_resolved": sum(s["resolves_count"] for s in steps),
                "critical_resolved": sum(s["critical_count"] for s in steps),
                "steps_without_fix": sum(1 for s in steps if not s["has_fix"]),
                "breaking_changes": sum(1 for s in steps if s["breaking_change_risk"] == "high"),
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

        if tool_name == "get_auto_fixable_findings":
            latest = await self._latest_scan_ids_for_user(user_project_query, args.get("project_id"), db)
            if not latest:
                return {"findings": [], "message": _ERR_NO_SCAN_DATA}
            limit = _clamp_limit(args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
            rows, ranking_note = await _ranked_findings(
                db,
                {
                    "scan_id": {"$in": list(latest.values())},
                    "severity": {"$in": ["CRITICAL", "HIGH"]},
                    "details.fixed_version": {"$exists": True, "$ne": None},
                    "waived": {"$ne": True},
                },
                limit,
            )
            names = await self._project_names(db, list({_row_project_id(f) for f in rows}))
            out = []
            for f in rows:
                slim = _serialize_finding_for_llm(f)
                slim["project_name"] = names.get(_row_project_id(f), "")
                out.append(slim)
            return {
                "findings": out,
                "count": len(out),
                "hint": "These already have a fix_version — recommend the upgrade directly.",
                **({"ranking_note": ranking_note} if ranking_note else {}),
            }

        if tool_name == "suggest_waiver_for_finding":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            finding = await db["findings"].find_one(
                {"finding_id": args["finding_id"], "project_id": args["project_id"]}
            )
            if not finding:
                return {"error": _ERR_FINDING_NOT_FOUND}
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
                return {"error": _ERR_PROJECT_NOT_FOUND}
            scan_a_id = args.get("scan_id_a")
            scan_b_id = args.get("scan_id_b")
            if not scan_a_id or not scan_b_id:
                head_scan_id = await self._head_scan_id(project, db)
                preceding = await ScanRepository(db).get_preceding_scan(head_scan_id) if head_scan_id else None
                if not head_scan_id or not preceding:
                    return {"error": _ERR_NEED_TWO_SCANS}
                scan_b_id = head_scan_id
                scan_a_id = preceding.id

            scan_a = await db["scans"].find_one({"_id": scan_a_id, "project_id": args["project_id"]})
            scan_b = await db["scans"].find_one({"_id": scan_b_id, "project_id": args["project_id"]})
            if not scan_a or not scan_b:
                return {"error": _ERR_SCAN_NOT_FOUND_IN_PROJECT}

            findings_response = await compute_findings_delta(
                db,
                project_id=args["project_id"],
                from_scan=scan_a_id,
                to_scan=scan_b_id,
                page=1,
                page_size=int(args.get("page_size") or 50),
                change=None,
                severity=_ensure_list(args.get("severity")),
                finding_type=_ensure_list(args.get("finding_type")),
            )
            return findings_response.model_dump(mode="json")

        if tool_name == "get_kev_findings":
            latest = await self._latest_scan_ids_for_user(user_project_query, args.get("project_id"), db)
            if not latest:
                return {"findings": [], "message": _ERR_NO_SCAN_DATA}
            limit = _clamp_limit(args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
            rows, ranking_note = await _ranked_findings(
                db,
                {
                    "scan_id": {"$in": list(latest.values())},
                    "details.exploit_maturity": {"$in": list(KEV_EQUIVALENT_MATURITY)},
                    "waived": {"$ne": True},
                },
                limit,
            )
            names = await self._project_names(db, list({_row_project_id(f) for f in rows}))
            out = []
            for f in rows:
                slim = _serialize_finding_for_llm(f)
                slim["project_name"] = names.get(_row_project_id(f), "")
                out.append(slim)
            return {
                "findings": out,
                "count": len(out),
                "hint": ("All of these have real-world exploits. Prioritise above plain CVSS-only critical findings."),
                **({"ranking_note": ranking_note} if ranking_note else {}),
            }

        if tool_name == "find_component_usage":
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            if not project_ids:
                return {"matches": [], "message": "No accessible projects"}
            latest = await self._latest_scan_ids_for_user(user_project_query, None, db)
            latest_scan_ids = list(latest.values())
            # The caller may quote a finding's group-qualified component; the inventory
            # stores the bare artifact name, so search on that too.
            wanted = args["component_name"]
            patterns = {wanted, artifact_segment(wanted)}
            dep_query: dict[str, Any] = {
                "name": {"$in": [re.compile(re.escape(p), re.IGNORECASE) for p in patterns if p]},
                "scan_id": {"$in": latest_scan_ids},
            }
            if args.get("version"):
                dep_query["version"] = args["version"]
            rows, rows_total = await bounded_read(
                db["dependencies"],
                dep_query,
                subject="dependency rows naming this component",
                limit=_COMPONENT_USAGE_READ,
                projection={
                    "name": 1,
                    "version": 1,
                    "project_id": 1,
                    "direct": 1,
                    "direct_inferred": 1,
                    "purl": 1,
                    "license": 1,
                },
            )
            names = await self._project_names(db, list({_row_project_id(r) for r in rows}))
            matches = []
            for r in rows:
                matches.append(
                    {
                        "project_id": r.get("project_id"),
                        "project_name": names.get(_row_project_id(r), ""),
                        "component": r.get("name"),
                        "version": r.get("version"),
                        "direct_dependency": bool(r.get("direct")),
                        "direct_confidence": _direct_confidence(r),
                        "purl": r.get("purl"),
                        "license": r.get("license"),
                    }
                )
            return {"matches": matches, "count": len(matches), "matches_total": rows_total}

        if tool_name == "get_findings_by_cve":
            cve = args["cve_id"].strip().upper()
            latest = await self._latest_scan_ids_for_user(user_project_query, None, db)
            if not latest:
                return {"findings": [], "message": _ERR_NO_SCAN_DATA}
            rows, rows_total = await bounded_read(
                db["findings"],
                {
                    "scan_id": {"$in": list(latest.values())},
                    _FIELD_VULN_ID: cve,
                },
                subject=f"findings naming {cve}",
                limit=_CVE_OCCURRENCE_READ,
            )
            names = await self._project_names(db, list({_row_project_id(f) for f in rows}))
            by_project: dict[str, dict[str, Any]] = {}
            for f in rows:
                pid = _row_project_id(f)
                slot = by_project.setdefault(
                    pid,
                    {
                        "project_id": pid,
                        "project_name": names.get(pid, ""),
                        "findings": [],
                    },
                )
                slot["findings"].append(_serialize_finding_for_llm(f))
            return {
                "cve_id": cve,
                "affected_projects": list(by_project.values()),
                # Projects and occurrences among the rows read; total_occurrences is the whole
                # population, so the two disagree exactly when the read saturated.
                "project_count": len(by_project),
                "occurrences_read": len(rows),
                "total_occurrences": rows_total,
            }

        if tool_name == "get_cve_details":
            cve = args["cve_id"].strip().upper()
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            if not project_ids:
                return {"error": "No accessible projects to source CVE data from"}
            finding = await db["findings"].find_one(
                {
                    "project_id": {"$in": project_ids},
                    _FIELD_VULN_ID: cve,
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
                "affected_component": f"{finding.get('component', '')}@{finding.get('version', '')}",
                "source_scanners": vuln.get("scanners"),
            }

        if tool_name == "get_stale_findings":
            from datetime import datetime as _dt
            from datetime import timedelta as _td
            from datetime import timezone as _tz

            days = _clamp_limit(args.get("days_open"), 30, maximum=MAX_DAY_WINDOW)
            limit = _clamp_limit(args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
            sev_min = (args.get("severity_min") or "HIGH").upper()
            allowed_sev = [
                s
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                if _SEVERITY_RANK.get(s, 0) >= _SEVERITY_RANK.get(sev_min, 3)
            ]
            latest = await self._latest_scan_ids_for_user(user_project_query, args.get("project_id"), db)
            if not latest:
                return {"findings": [], "message": _ERR_NO_SCAN_DATA}
            cutoff = _dt.now(_tz.utc) - _td(days=days)
            project_ids = list(latest.keys())
            old_keys: set[tuple[str, tuple[str, str, str]]] = set()
            async for f in db["findings"].find(
                {"project_id": {"$in": project_ids}, "created_at": {"$lt": cutoff}},
                {**FINDING_IDENTITY_PROJECTION, "project_id": 1},
            ):
                project_id = f.get("project_id")
                if project_id:
                    old_keys.update((project_id, identity) for identity in staleness_identities(f))
            if not old_keys:
                return {"findings": [], "message": f"No findings older than {days} days"}
            stale, ranking_note = await _ranked_findings(
                db,
                {"scan_id": {"$in": list(latest.values())}, "severity": {"$in": allowed_sev}},
                limit,
                keep=lambda f: any(
                    (_row_project_id(f), identity) in old_keys for identity in staleness_identities(f)
                ),
            )
            names = await self._project_names(db, list({_row_project_id(f) for f in stale}))
            out = []
            for f in stale:
                slim = _serialize_finding_for_llm(f)
                slim["project_name"] = names.get(_row_project_id(f), "")
                out.append(slim)
            return {
                "findings": out,
                "count": len(out),
                "days_open_threshold": days,
                "hint": (
                    "These findings have lingered for more than the threshold. "
                    "Suggest either fixing, waiving with justification, or escalating."
                ),
                **({"ranking_note": ranking_note} if ranking_note else {}),
            }

        if tool_name == "get_license_violations":
            latest = await self._latest_scan_ids_for_user(user_project_query, args.get("project_id"), db)
            if not latest:
                return {"findings": [], "message": _ERR_NO_SCAN_DATA}
            limit = _clamp_limit(args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
            rows, ranking_note = await _ranked_findings(
                db,
                {"scan_id": {"$in": list(latest.values())}, "type": "license"},
                limit,
            )
            names = await self._project_names(db, list({_row_project_id(f) for f in rows}))
            out = []
            for f in rows:
                slim = _serialize_finding_for_llm(f)
                slim["project_name"] = names.get(_row_project_id(f), "")
                out.append(slim)
            return {
                "findings": out,
                "count": len(out),
                **({"ranking_note": ranking_note} if ranking_note else {}),
            }

        if tool_name == "get_expiring_waivers":
            from datetime import datetime as _dt
            from datetime import timedelta as _td
            from datetime import timezone as _tz

            days = _clamp_limit(args.get("days"), 30, maximum=MAX_DAY_WINDOW)
            project_ids = await self._get_authorized_project_ids(user_project_query, db)
            now = _dt.now(_tz.utc)
            cutoff = now + _td(days=days)
            rows, rows_total = await bounded_read(
                db["waivers"],
                {
                    "$or": [
                        {"project_id": {"$in": project_ids}},
                        {"project_id": None},
                    ],
                    "expiration_date": {"$gte": now, "$lte": cutoff},
                },
                subject="waivers expiring in the window",
                limit=_EXPIRING_WAIVER_READ,
                sort=[("expiration_date", 1)],
            )
            names = await self._project_names(db, list({_row_project_id(r) for r in rows}))
            out = []
            for w in rows:
                expires = w.get("expiration_date")
                out.append(
                    {
                        "project_id": w.get("project_id"),
                        "project_name": names.get(_row_project_id(w), ""),
                        "finding_id": w.get("finding_id"),
                        "vulnerability_id": w.get("vulnerability_id"),
                        "reason": _clip_value(w.get("reason") or ""),
                        "expires_at": _clip_value(expires),
                        "package": f"{w.get('package_name', '')}@{w.get('package_version', '')}",
                    }
                )
            return {"waivers": out, "count": len(out), "waivers_total": rows_total, "window_days": days}

        if tool_name == "get_team_risk_overview":
            team = await team_repo.get_by_id(args["team_id"])
            if not team:
                return {"error": _ERR_TEAM_NOT_FOUND}
            if not await team_repo.is_member(args["team_id"], str(user.id)) and not has_permission(
                user.permissions, Permissions.TEAM_READ_ALL
            ):
                return {"error": _ERR_ACCESS_DENIED}
            projects, projects_total = await bounded_read(
                db["projects"],
                {"team_id": args["team_id"]},
                subject="team projects",
                limit=_TEAM_RISK_PROJECT_READ,
                projection={"_id": 1, "name": 1, "stats": 1, "last_scan_at": 1},
            )
            totals: dict[str, int] = {}
            risky = []
            for p in projects:
                stats = p.get("stats") or {}
                for sev in ("critical", "high", "medium", "low"):
                    totals[sev] = totals.get(sev, 0) + int(stats.get(sev, 0) or 0)
                risky.append(
                    (
                        int(stats.get("critical", 0) or 0),
                        int(stats.get("high", 0) or 0),
                        p.get("_id"),
                        p.get("name", ""),
                    )
                )
            risky.sort(reverse=True)
            top3 = [
                {"project_id": pid, "project_name": name, "critical": c, "high": h} for c, h, pid, name in risky[:3]
            ]
            return {
                "team_id": args["team_id"],
                "team_name": getattr(team, "name", ""),
                # Totals are summed over the projects read; project_count is the team's whole
                # holding, so the two disagree exactly when the read saturated.
                "projects_summed": len(projects),
                "project_count": projects_total,
                "severity_totals": totals,
                "top_risky_projects": top3,
            }

        if tool_name == "get_projects_without_recent_scan":
            from datetime import datetime as _dt
            from datetime import timedelta as _td
            from datetime import timezone as _tz

            days = _clamp_limit(args.get("days"), 14, maximum=MAX_DAY_WINDOW)
            limit = _clamp_limit(args.get("limit"), 10, maximum=MAX_SUMMARY_ROWS)
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
                out.append(
                    {
                        "project_id": p.get("_id"),
                        "project_name": p.get("name", ""),
                        "last_scan_at": _clip_value(last),
                        "never_scanned": last is None,
                    }
                )
            return {"projects": out, "count": len(out), "threshold_days": days}

        if tool_name in ("get_callgraph", "check_reachability"):
            project = await self._get_authorized_project(args.get("project_id", ""), user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            if tool_name == "get_callgraph":
                # The newest graph the project has, not head's: uploading one is a separate opt-in
                # CI step, so scoping to head would blank the tool out for most projects. The
                # response carries scan_id and created_at so the answer can say which build it is.
                doc = await db["callgraphs"].find_one(
                    {"project_id": args["project_id"]},
                    _CALLGRAPH_SUMMARY_PROJECTION,
                    sort=[("created_at", -1)],
                )
                return {"callgraph": _serialize_doc(doc) if doc else None}
            finding = await db["findings"].find_one({"_id": args["finding_id"], "project_id": args["project_id"]})
            if not finding:
                return {"error": _ERR_FINDING_NOT_FOUND}
            reachability = (finding.get("details") or {}).get("reachability") or {}
            is_reachable = finding.get("reachable")
            analysis_level = finding.get("reachability_level")
            return {
                "finding_id": args["finding_id"],
                "is_reachable": is_reachable,
                "status": reachability_display_tier(is_reachable, analysis_level),
                "analysis_level": analysis_level,
                "confidence_score": reachability.get("confidence_score"),
            }

        if tool_name == "list_archives":
            query = {}
            if args.get("project_id"):
                project = await self._get_authorized_project(args["project_id"], user_project_query, db)
                if not project:
                    return {"error": _ERR_PROJECT_NOT_FOUND}
                query["project_id"] = args["project_id"]
            elif not has_permission(user.permissions, Permissions.ARCHIVE_READ_ALL):
                project_ids = await self._get_authorized_project_ids(user_project_query, db)
                query["project_id"] = {"$in": project_ids}
            limit = _clamp_limit(args.get("limit"), 20, maximum=MAX_SUMMARY_ROWS)
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

        if tool_name == "list_project_webhooks":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            webhooks, webhooks_total = await bounded_read(
                db["webhooks"], {"project_id": args["project_id"]}, subject="webhooks", limit=_WEBHOOK_READ
            )
            return {
                "webhooks": [_serialize_doc(w) for w in webhooks],
                "webhooks_total": webhooks_total,
            }

        if tool_name == "get_webhook_deliveries":
            webhook = await db["webhooks"].find_one({"_id": args["webhook_id"]})
            if not webhook:
                return {"error": "Webhook not found"}
            project = await self._get_authorized_project(webhook.get("project_id", ""), user_project_query, db)
            if not project:
                return {"error": _ERR_ACCESS_DENIED}
            deliveries, deliveries_total = await bounded_read(
                db["webhook_deliveries"],
                {"webhook_id": args["webhook_id"]},
                subject="webhook deliveries",
                limit=_WEBHOOK_DELIVERY_READ,
                sort=[("timestamp", -1)],
            )
            return {
                "deliveries": [_serialize_doc(d) for d in deliveries],
                "deliveries_total": deliveries_total,
            }

        if tool_name == "get_system_settings":
            doc = await db["system_settings"].find_one({"_id": "current"})
            return {"settings": _serialize_doc(doc) if doc else {}}

        if tool_name == "get_system_health":
            from app.core.cache import cache_service

            cache_health = await cache_service.health_check()
            return {"database": "connected", "cache": cache_health}

        if tool_name == "list_crypto_assets":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            answer_scan = await self._scan_under_answer(project, args.get("scan_id"), db)
            if not answer_scan:
                return {"error": _scan_lookup_error(args.get("scan_id"))}
            scan_id, build = answer_scan
            assets = await list_crypto_assets(
                db,
                project_id=args["project_id"],
                scan_id=scan_id,
                asset_type=args.get("asset_type"),
                primitive=args.get("primitive"),
                name_search=args.get("name_search"),
                skip=int(args.get("skip") or 0),
                limit=_clamp_limit(args.get("limit"), 100, MAX_CRYPTO_ASSET_PAGE),
            )
            return {**assets, "scan": build}

        if tool_name == "get_crypto_asset_details":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            result = await get_crypto_asset_details(db, project_id=args["project_id"], asset_id=args["asset_id"])
            return result if result is not None else {"error": "Crypto asset not found"}

        if tool_name == "get_crypto_summary":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            answer_scan = await self._scan_under_answer(project, args.get("scan_id"), db)
            if not answer_scan:
                return {"error": _scan_lookup_error(args.get("scan_id"))}
            scan_id, build = answer_scan
            summary = await get_crypto_summary(db, project_id=args["project_id"], scan_id=scan_id)
            return {**summary, "scan": build}

        if tool_name == "get_project_crypto_policy":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            return await get_project_crypto_policy(db, project_id=args["project_id"])

        if tool_name == "suggest_crypto_policy_override":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            answer_scan = await self._scan_under_answer(project, args.get("scan_id"), db)
            if not answer_scan:
                return {"error": _scan_lookup_error(args.get("scan_id"))}
            scan_id, build = answer_scan
            advice = await suggest_crypto_policy_override(db, project_id=args["project_id"], scan_id=scan_id)
            return {**advice, "scan": build}

        if tool_name == "get_crypto_hotspots":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            return await get_crypto_hotspots(
                db,
                project_id=args["project_id"],
                group_by=args.get("group_by", "name"),
                limit=_clamp_limit(args.get("limit"), 20, MAX_CRYPTO_HOTSPOT_PAGE),
            )

        if tool_name == "get_crypto_trends":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            return await get_crypto_trends(
                db,
                project_id=args["project_id"],
                metric=args.get("metric", "total_crypto_findings"),
                days=int(args.get("days") or 30),
            )

        if tool_name == "get_scan_delta":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            from_scan_id = args["from_scan_id"]
            to_scan_id = args["to_scan_id"]
            scan_a = await db["scans"].find_one({"_id": from_scan_id, "project_id": args["project_id"]})
            scan_b = await db["scans"].find_one({"_id": to_scan_id, "project_id": args["project_id"]})
            if not scan_a or not scan_b:
                return {"error": _ERR_SCAN_NOT_FOUND_IN_PROJECT}
            crypto_response = await compute_crypto_delta_envelope(
                db,
                project_id=args["project_id"],
                from_scan=from_scan_id,
                to_scan=to_scan_id,
                page=1,
                page_size=int(args.get("page_size") or 50),
                change=None,
            )
            return crypto_response.model_dump(mode="json")

        if tool_name == "generate_pqc_migration_plan":
            project = await self._get_authorized_project(args["project_id"], user_project_query, db)
            if not project:
                return {"error": _ERR_PROJECT_NOT_FOUND}
            return await generate_pqc_migration_plan(
                db,
                user=user,
                project_id=args["project_id"],
                limit=_clamp_limit(args.get("limit"), 500, MAX_PQC_PLAN_ITEMS),
            )

        if tool_name == "list_compliance_reports":
            project_id = args.get("project_id")
            if project_id:
                project = await self._get_authorized_project(project_id, user_project_query, db)
                if not project:
                    return {"error": _ERR_PROJECT_NOT_FOUND}
                return await list_compliance_reports(
                    db,
                    project_id=project_id,
                    framework=args.get("framework"),
                    limit=_clamp_limit(args.get("limit"), 10, MAX_COMPLIANCE_REPORT_PAGE),
                )
            # No project_id: restrict to the caller's visibility, else the repo
            # query is unfiltered and leaks every scope's reports org-wide.
            from app.services.chat import tools as _pkg

            authorized_project_ids = await self._get_authorized_project_ids(user_project_query, db)
            visibility = await self._compliance_visibility_filter(user, authorized_project_ids, team_repo)
            framework = args.get("framework")
            fw: Any | None = None
            if framework:
                try:
                    fw = _pkg.ReportFramework(framework)
                except ValueError:
                    fw = None
            reports = await _pkg.ComplianceReportRepository(db).list(
                framework=fw,
                limit=_clamp_limit(args.get("limit"), 10, MAX_COMPLIANCE_REPORT_PAGE),
                extra_filter=visibility,
            )
            return {"reports": [r.model_dump(by_alias=True) for r in reports]}

        if tool_name == "list_policy_audit_entries":
            project_id = args.get("project_id")
            # System-scope audit is admin-only (system:manage).
            if args.get("policy_scope") == "system":
                if not has_permission(user.permissions, Permissions.SYSTEM_MANAGE):
                    return {"error": _ERR_ACCESS_DENIED}
            elif project_id:
                project = await self._get_authorized_project(project_id, user_project_query, db)
                if not project:
                    return {"error": _ERR_PROJECT_NOT_FOUND}
            return await list_policy_audit_entries(
                db,
                policy_scope=args["policy_scope"],
                project_id=project_id,
                limit=_clamp_limit(args.get("limit"), 20, MAX_POLICY_AUDIT_PAGE),
            )

        if tool_name == "get_framework_evaluation_summary":
            scope = args["scope"]
            scope_id = args.get("scope_id")
            if scope == "project" and scope_id:
                project = await self._get_authorized_project(scope_id, user_project_query, db)
                if not project:
                    return {"error": _ERR_PROJECT_NOT_FOUND}
            return await get_framework_evaluation_summary(
                db,
                user=user,
                scope=scope,
                scope_id=scope_id,
                framework=args["framework"],
            )

        return {"error": f"Unknown tool: {tool_name}"}

    async def _get_authorized_project(
        self, project_id: str, user_project_query: dict[str, Any], db: AsyncIOMotorDatabase
    ) -> dict[str, Any] | None:
        """Fetch a project only if the user has access.

        `user_project_query` MUST come from build_user_project_query (returns {}
        only for PROJECT_READ_ALL users). $and, not .update(), avoids a silent
        authorization bypass if that query ever carried an `_id` key.
        """
        if not user_project_query:
            return await db["projects"].find_one({"_id": project_id})
        return await db["projects"].find_one({"$and": [{"_id": project_id}, user_project_query]})

    async def _compliance_visibility_filter(
        self,
        user: User,
        authorized_project_ids: list[str],
        team_repo: TeamRepository,
    ) -> dict[str, Any]:
        """Build the ``$or`` visibility filter for compliance reports, mirroring compliance_reports._build_visibility_filter."""
        perms = getattr(user, "permissions", []) or []
        is_super = has_permission(perms, Permissions.SYSTEM_MANAGE)
        user_id = str(user.id)

        branches: list[dict[str, Any]] = []
        user_branch: dict[str, Any] = {"scope": "user"}
        if not is_super:
            user_branch["requested_by"] = user_id
        branches.append(user_branch)

        if authorized_project_ids:
            branches.append({"scope": "project", "scope_id": {"$in": authorized_project_ids}})

        user_teams = await team_repo.find_by_member(user_id)
        team_ids = [str(t.id) for t in user_teams]
        if team_ids:
            branches.append({"scope": "team", "scope_id": {"$in": team_ids}})

        if is_super or has_permission(perms, Permissions.ANALYTICS_GLOBAL):
            branches.append({"scope": "global"})

        return {"$or": branches}

    async def _get_authorized_project_ids(
        self, user_project_query: dict[str, Any], db: AsyncIOMotorDatabase
    ) -> list[str]:
        """Every accessible project id, up to the read ceiling. A cut here narrows every
        estate-wide answer built on it, so it is recorded for the call's disclosure."""
        projects, _total = await bounded_read(
            db["projects"],
            user_project_query,
            subject="accessible projects",
            limit=_AUTHORIZED_PROJECT_READ,
            projection={"_id": 1},
        )
        return [p["_id"] for p in projects]

    async def _head_scan_id(self, project: dict[str, Any], db: AsyncIOMotorDatabase) -> str | None:
        """The scan representing the head of a project the caller already read and authorised."""
        project_id: str = project["_id"]
        return (await ScanRepository(db).get_latest_active_scan_ids([project])).get(project_id)

    async def _scan_under_answer(
        self, project: dict[str, Any], requested_scan_id: str | None, db: AsyncIOMotorDatabase
    ) -> tuple[str, dict[str, Any]] | None:
        """The build a scan-scoped tool answers about, with the block that names it. No scan_id means
        head; a caller that names one gets it, labelled against head, because a relayed answer carries
        no chart beside it against which a reader could notice the wrong build."""
        head_scan_id = await self._head_scan_id(project, db)
        scan_id = requested_scan_id or head_scan_id
        if not scan_id:
            return None
        doc = await db["scans"].find_one({"_id": scan_id, "project_id": project["_id"]}, _BUILD_PROJECTION)
        if not doc:
            return None
        return scan_id, {
            "scan_id": scan_id,
            "branch": doc.get("branch"),
            "commit_hash": doc.get("commit_hash"),
            "created_at": _clip_value(doc.get("created_at")),
            "status": doc.get("status"),
            "is_head": scan_id == head_scan_id,
        }

    async def _head_scan_stats(self, db: AsyncIOMotorDatabase, head: dict[str, str]) -> dict[str, dict[str, Any]]:
        """project_id -> the stats block of that project's head scan."""
        if not head:
            return {}
        stats: dict[str, dict[str, Any]] = {}
        async for scan in db["scans"].find({"_id": {"$in": list(head.values())}}, {"project_id": 1, "stats": 1}):
            project_id = scan.get("project_id")
            if project_id:
                stats[project_id] = scan.get("stats") or {}
        return stats

    async def _latest_scan_ids_for_user(
        self,
        user_project_query: dict[str, Any],
        restrict_to_project_id: str | None,
        db: AsyncIOMotorDatabase,
    ) -> dict[str, str]:
        """Return {project_id: head scan id} for authorised projects, validated against
        `restrict_to_project_id` when provided (returns {} on access denial)."""
        from app.services.releases import resolve_scan_ids

        if restrict_to_project_id:
            project = await self._get_authorized_project(restrict_to_project_id, user_project_query, db)
            if not project:
                return {}
            scan_id = await self._head_scan_id(project, db)
            return {restrict_to_project_id: scan_id} if scan_id else {}

        project_ids = await self._get_authorized_project_ids(user_project_query, db)
        if not project_ids:
            return {}

        return await resolve_scan_ids(db, project_ids)

    @staticmethod
    async def _project_names(db: AsyncIOMotorDatabase, project_ids: list[str]) -> dict[str, str]:
        cleaned = [pid for pid in project_ids if pid]
        if not cleaned:
            return {}
        names: dict[str, str] = {}
        async for p in db["projects"].find({"_id": {"$in": cleaned}}, {"name": 1}):
            names[p["_id"]] = p.get("name", "")
        return names
