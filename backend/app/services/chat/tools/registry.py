"""Central dispatcher for chat tool calls with permission checks and result post-processing."""

import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, ValidationError

from app.api.v1.helpers.projects import authorize_waiver_read, build_user_project_query
from app.api.v1.helpers.teams import check_team_access, resolve_team_names, team_refs, visible_teams_filter
from app.api.v1.helpers.webhooks import (
    check_team_webhook_list_permission,
    check_webhook_list_permission,
    check_webhook_permission,
)
from app.core.constants import (
    MAX_COMPLIANCE_REPORT_PAGE,
    MAX_CRYPTO_ASSET_PAGE,
    MAX_CRYPTO_HOTSPOT_PAGE,
    MAX_POLICY_AUDIT_PAGE,
    MAX_PQC_PLAN_ITEMS,
)
from app.core.metrics import chat_tool_calls_total, chat_tool_duration_seconds
from app.core.permissions import Permissions, has_permission
from app.models.finding import FindingType, Severity
from app.models.project import Project
from app.models.user import User
from app.models.waiver import is_waiver_active
from app.models.webhook import Webhook
from app.repositories.base import and_filters
from app.repositories.scans import ScanRepository
from app.repositories.teams import TeamRepository
from app.schemas.system import SystemSettingsResponse
from app.schemas.webhook import WebhookResponse
from app.services.aggregation.components import artifact_segment, build_component_index, lookup_component
from app.services.analytics.crypto_delta import compute_crypto_delta_envelope
from app.services.analytics.findings_delta import FINDING_IDENTITY_PROJECTION, compute_findings_delta
from app.services.analytics.scopes import ScopeResolutionError, ScopeTooLargeError, read_scope_projects
from app.services.analyzers.purl_utils import canonical_purl
from app.services.compliance.visibility import report_visibility_filter
from app.services.reachability_enrichment import reachability_display_tier

from ._arguments import ToolArgumentError, checked_arguments
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
_ERR_TEAM_NOT_FOUND = "Team not found or access denied"
_ERR_ACCESS_DENIED = "Access denied"
_ERR_WEBHOOK_NOT_FOUND = "Webhook not found or access denied"
_ERR_ARCHIVE_NOT_FOUND = "Archive not found or access denied"
_ERR_NO_SCAN_DATA = "No scan data available"
_ERR_NEED_TWO_SCANS = "Need at least two builds on the head branch to compare"
_FIELD_VULN_ID = "details.vulnerabilities.id"
_FIELD_EPSS_SCORE = "details.epss_score"


def _rendered_fields(model: type[BaseModel], *, withheld: frozenset[str] = frozenset()) -> list[str]:
    """Keys a REST response model renders, read off its fields since a validation error quotes the secrets."""
    return [
        "_id" if name == "id" else name
        for name, field in model.model_fields.items()
        if not field.exclude and name not in withheld
    ]


_PROJECT_FIELDS = _rendered_fields(Project)
# Custom headers hold receiver credentials, and a tool answer leaves the process for the LLM provider.
_WEBHOOK_FIELDS = _rendered_fields(WebhookResponse, withheld=frozenset({"headers"}))

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
_TEAM_LIST_READ = 100
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

# A breakdown groups over a closed enum, so its read bound is the size of that enum: any smaller
# number returns some of the buckets under a key that reads as all of them.
_SEVERITY_BUCKETS = len(Severity)
_FINDING_TYPE_BUCKETS = len(FindingType)

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


class _ToolRefusal(Exception):
    """The answer a handler stops with; `_dispatch` returns it as the tool's error."""


async def _gated[T](check: Awaitable[T], refusal: str) -> T:
    """REST's access check, its HTTP refusal turned into the tool's own answer."""
    try:
        return await check
    except HTTPException:
        raise _ToolRefusal(refusal) from None


@dataclass(frozen=True, slots=True)
class _ToolContext:
    """Resolved once in `_dispatch` so no handler re-derives the caller's visibility query."""

    args: dict[str, Any]
    user: User
    db: AsyncIOMotorDatabase
    user_project_query: dict[str, Any]


_ToolHandler = Callable[["ChatToolRegistry", _ToolContext], Awaitable[dict[str, Any]]]


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
        arguments: Any,
        user: User,
        db: AsyncIOMotorDatabase,
    ) -> dict[str, Any]:
        if tool_name not in self._HANDLERS:
            logger.warning("chat tool not found: %s", tool_name)
            # A model-invented name as a label would open a new series per hallucination.
            chat_tool_calls_total.labels(tool_name="unknown", status="unknown").inc()
            return {"error": f"Unknown tool: {tool_name}"}
        required = TOOL_PERMISSIONS.get(tool_name)
        if required and not has_permission(user.permissions, required):
            chat_tool_calls_total.labels(tool_name=tool_name, status="denied").inc()
            return {"error": f"You don't have permission to use {tool_name}"}

        start = time.perf_counter()
        status = "error"
        try:
            args = checked_arguments(tool_name, arguments)
            begin_limit_ledger()
            result = await self._dispatch(tool_name, args, user, db)
            status = "rejected" if "error" in result else "success"
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
            return _truncate_if_too_large(result)
        except ToolArgumentError as e:
            status = "rejected"
            return {"error": str(e)}
        except (ScopeTooLargeError, ScopeResolutionError) as e:
            status = "refused"
            return {"error": str(e)}
        except Exception as e:
            logger.exception(f"Tool {tool_name} failed: {e}")
            return {"error": f"Tool execution failed: {e!s}"}
        finally:
            chat_tool_calls_total.labels(tool_name=tool_name, status=status).inc()
            chat_tool_duration_seconds.labels(tool_name=tool_name).observe(time.perf_counter() - start)

    async def _dispatch(
        self,
        tool_name: str,
        args: dict[str, Any],
        user: User,
        db: AsyncIOMotorDatabase,
    ) -> dict[str, Any]:
        ctx = _ToolContext(
            args=args, user=user, db=db, user_project_query=await build_user_project_query(user, TeamRepository(db))
        )
        try:
            return await self._HANDLERS[tool_name](self, ctx)
        except _ToolRefusal as refusal:
            return {"error": str(refusal)}

    async def _tool_list_projects(self, ctx: _ToolContext) -> dict[str, Any]:
        search = ctx.args.get("search")
        name_filter = {"name": {"$regex": re.escape(search), "$options": "i"}} if search else {}
        query = and_filters(ctx.user_project_query, name_filter)
        limit = _clamp_limit(ctx.args.get("limit"), 15, maximum=MAX_SUMMARY_ROWS)
        cursor = ctx.db["projects"].find(query, sort=[("last_scan_at", -1)], limit=limit)
        projects = await cursor.to_list(length=limit)
        team_names = await resolve_team_names(ctx.db, {tid for p in projects for tid in p.get("team_ids") or []})
        rows = []
        for p in projects:
            row = _serialize_doc(p, ["_id", "name", "stats", "last_scan_at", "created_at"])
            row["teams"] = [ref.model_dump() for ref in team_refs(p.get("team_ids") or [], team_names)]
            rows.append(row)
        return {"projects": rows, "count": len(rows)}

    async def _tool_get_project_details(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        return {"project": _serialize_doc(project, _PROJECT_FIELDS)}

    async def _tool_get_project_members(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        return {"members": project.get("members", [])}

    async def _tool_get_project_settings(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
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

    async def _tool_get_scan_history(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        limit = _clamp_limit(ctx.args.get("limit"), 10, maximum=MAX_SUMMARY_ROWS)
        # Newest-first across every branch and status, so the first row is a queued run on a
        # branch nobody ships as often as it is the build the project stands on.
        cursor = ctx.db["scans"].find({"project_id": project["_id"]}, sort=[("created_at", -1)], limit=limit)
        scans = await cursor.to_list(length=limit)
        head_scan_id = await self._head_scan_id(project, ctx.db)
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

    async def _tool_get_scan_details(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        scan_id, build = await self._scan_under_answer(ctx, project)
        scan = await ctx.db["scans"].find_one({"_id": scan_id, "project_id": project["_id"]})
        return {"scan": {**_serialize_doc(scan), "is_head": build["is_head"]}}

    async def _tool_get_scan_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        scan_id, build = await self._scan_under_answer(ctx, project)
        query = {"scan_id": scan_id, "project_id": project["_id"]}
        if ctx.args.get("severity"):
            query["severity"] = ctx.args["severity"].upper()
        if ctx.args.get("type"):
            query["type"] = ctx.args["type"]
        limit = _clamp_limit(ctx.args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
        findings, ranking_note = await _ranked_findings(ctx.db, query, limit)
        return {
            "findings": [_serialize_finding_for_llm(f) for f in findings],
            "count": len(findings),
            "scan": build,
            **({"ranking_note": ranking_note} if ranking_note else {}),
        }

    async def _tool_get_project_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        head_scan_id = await self._head_scan_id(project, ctx.db)
        if not head_scan_id:
            return {"findings": [], "count": 0, "message": "No scans found for this project"}
        query = {"scan_id": head_scan_id}
        if ctx.args.get("severity"):
            query["severity"] = ctx.args["severity"].upper()
        if ctx.args.get("type"):
            query["type"] = ctx.args["type"]
        limit = _clamp_limit(ctx.args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
        findings, ranking_note = await _ranked_findings(ctx.db, query, limit)
        return {
            "findings": [_serialize_finding_for_llm(f) for f in findings],
            "count": len(findings),
            "project_name": project.get("name"),
            **({"ranking_note": ranking_note} if ranking_note else {}),
        }

    async def _tool_get_vulnerability_details(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        finding = await ctx.db["findings"].find_one({"_id": ctx.args["finding_id"], "project_id": project["_id"]})
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

    async def _tool_search_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        search_query = ctx.args["query"]
        escaped_search_query = re.escape(search_query)
        query = {
            **await self._in_scope(ctx),
            "$or": [
                {"finding_id": {"$regex": escaped_search_query, "$options": "i"}},
                {"description": {"$regex": escaped_search_query, "$options": "i"}},
                {"component": {"$regex": escaped_search_query, "$options": "i"}},
                {_FIELD_VULN_ID: {"$regex": escaped_search_query, "$options": "i"}},
            ],
        }
        if ctx.args.get("severity"):
            query["severity"] = ctx.args["severity"].upper()
        if ctx.args.get("type"):
            query["type"] = ctx.args["type"]
        limit = _clamp_limit(ctx.args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
        cursor = ctx.db["findings"].find(query, limit=limit)
        findings = await cursor.to_list(length=limit)
        names = await self._project_names(ctx.db, list({_row_project_id(f) for f in findings}))
        out = []
        for f in findings:
            slim = _serialize_finding_for_llm(f)
            slim["project_name"] = names.get(_row_project_id(f), "")
            out.append(slim)
        return {"findings": out, "count": len(out)}

    async def _tool_get_findings_by_severity(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        head_scan_id = await self._head_scan_id(project, ctx.db)
        if not head_scan_id:
            return {"breakdown": {}}
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": head_scan_id}},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]
        results = await ctx.db["findings"].aggregate(pipeline).to_list(length=_SEVERITY_BUCKETS)
        return {"breakdown": {r["_id"]: r["count"] for r in results}}

    async def _tool_get_findings_by_type(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        head_scan_id = await self._head_scan_id(project, ctx.db)
        if not head_scan_id:
            return {"breakdown": {}}
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": head_scan_id}},
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
        ]
        results = await ctx.db["findings"].aggregate(pipeline).to_list(length=_FINDING_TYPE_BUCKETS)
        return {"breakdown": {r["_id"]: r["count"] for r in results}}

    async def _tool_get_analytics_summary(self, ctx: _ToolContext) -> dict[str, Any]:
        head, names = await self._heads_in_scope(ctx)
        if not names:
            return {"total_projects": 0, "total_findings": 0, "severity_breakdown": {}}
        stats_by_project = await self._head_scan_stats(ctx.db, head)
        sev_pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": list(head.values())}}},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]
        sev_results = await ctx.db["findings"].aggregate(sev_pipeline).to_list(length=_SEVERITY_BUCKETS)
        ranked = sorted(head, key=lambda pid: (-_stat(stats_by_project.get(pid), "critical"), pid))[:_TOP_RISKY]
        top3 = [
            {
                "project_id": pid,
                "project_name": names.get(pid, ""),
                "critical": _stat(stats_by_project.get(pid), "critical"),
                "high": _stat(stats_by_project.get(pid), "high"),
            }
            for pid in ranked
        ]
        return {
            "total_projects": len(names),
            "severity_breakdown": {r["_id"]: r["count"] for r in sev_results},
            "total_findings": sum(r["count"] for r in sev_results),
            "top_risky_projects": top3,
            "hint": (
                "If the user asked 'where should I start' or 'what is worst', "
                "name the top_risky_projects directly instead of re-emitting the "
                "severity breakdown."
            ),
        }

    async def _tool_get_risk_trends(self, ctx: _ToolContext) -> dict[str, Any]:
        days = ctx.args.get("days", 30)
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        if ctx.args.get("project_id"):
            scope = {"project_id": (await self._require_project(ctx))["_id"]}
        else:
            scope = await self._in_scope(ctx)
        match_query: dict[str, Any] = {**scope, "created_at": {"$gte": cutoff}}
        scans, scans_total = await bounded_read(
            ctx.db["scans"],
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

    async def _tool_get_dependency_tree(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        head_scan_id = await self._head_scan_id(project, ctx.db)
        if not head_scan_id:
            return {"dependencies": []}
        deps, deps_total = await bounded_read(
            ctx.db["dependencies"],
            {"scan_id": head_scan_id},
            subject="dependencies",
            limit=_DEPENDENCY_TREE_READ,
        )
        return {
            "dependencies": [_serialize_doc(d) for d in deps],
            "dependencies_total": deps_total,
        }

    async def _tool_get_hotspots(self, ctx: _ToolContext) -> dict[str, Any]:
        limit = _clamp_limit(ctx.args.get("limit"), 10, maximum=MAX_SUMMARY_ROWS)
        head, names = await self._heads_in_scope(ctx)
        stats_by_project = await self._head_scan_stats(ctx.db, head)
        ranked = sorted(head, key=lambda pid: (-_stat(stats_by_project.get(pid), "critical"), pid))[:limit]
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

    async def _tool_get_dependency_details(self, ctx: _ToolContext) -> dict[str, Any]:
        dep = await ctx.db["dependency_enrichments"].find_one({"purl": canonical_purl(ctx.args["dependency_name"])})
        if not dep:
            dep = await ctx.db["dependency_enrichments"].find_one(
                {"name": {"$regex": re.escape(ctx.args["dependency_name"]), "$options": "i"}}
            )
        if not dep:
            return {"error": "Dependency not found in enrichment data"}
        return {"dependency": _serialize_doc(dep)}

    async def _tool_list_teams(self, ctx: _ToolContext) -> dict[str, Any]:
        visible = visible_teams_filter(ctx.user)
        if visible is None:
            return {"error": _ERR_ACCESS_DENIED}
        teams, teams_total = await bounded_read(
            ctx.db["teams"],
            visible,
            subject="teams",
            limit=_TEAM_LIST_READ,
            sort=[("name", 1)],
            projection={"name": 1, "description": 1},
        )
        return {
            "teams": [{"id": t["_id"], "name": t.get("name"), "description": t.get("description")} for t in teams],
            "teams_total": teams_total,
        }

    async def _tool_get_team_details(self, ctx: _ToolContext) -> dict[str, Any]:
        team = await _gated(check_team_access(ctx.args.get("team_id", ""), ctx.user, ctx.db), _ERR_TEAM_NOT_FOUND)
        return {
            "team": {
                "id": team.id,
                "name": team.name,
                "description": team.description,
                "members": [m.model_dump() for m in team.members],
            }
        }

    async def _tool_get_team_projects(self, ctx: _ToolContext) -> dict[str, Any]:
        team = await _gated(check_team_access(ctx.args.get("team_id", ""), ctx.user, ctx.db), _ERR_TEAM_NOT_FOUND)
        query = and_filters(ctx.user_project_query, {"team_ids": team.id})
        projects, projects_total = await bounded_read(
            ctx.db["projects"], query, subject="team projects", limit=_TEAM_PROJECT_READ
        )
        return {
            "projects": [_serialize_doc(p, ["_id", "name", "stats", "last_scan_at"]) for p in projects],
            "projects_total": projects_total,
        }

    async def _tool_get_waiver_status(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        head_scan_id = await self._head_scan_id(project, ctx.db)
        finding = None
        if head_scan_id:
            finding = await ctx.db["findings"].find_one(
                {"scan_id": head_scan_id, "finding_id": ctx.args["finding_id"]},
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
        waiver = await ctx.db["waivers"].find_one(
            {"finding_id": ctx.args["finding_id"], "project_id": project["_id"]}
        ) or await ctx.db["waivers"].find_one({"finding_id": ctx.args["finding_id"], "project_id": None})
        if not waiver:
            return {"waived": False}
        active = is_waiver_active(waiver.get("expiration_date"), now)
        serialized = {**_serialize_doc(waiver), "is_active": active}
        if active:
            return {
                "waived": False,
                "waiver_present": True,
                "suppressing": False,
                "reason": "no matching finding in the latest scan — finding fixed/moved or waiver dormant",
                "waiver": serialized,
            }
        return {"waived": False, "expired_waiver": serialized}

    async def _tool_list_project_waivers(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await ctx.db["projects"].find_one({"_id": ctx.args.get("project_id")}, {"_id": 1})
        if not project:
            return {"error": _ERR_PROJECT_NOT_FOUND}
        await _gated(authorize_waiver_read(project["_id"], ctx.user, ctx.db), _ERR_PROJECT_NOT_FOUND)
        now = datetime.now(timezone.utc)
        waivers, waivers_total = await bounded_read(
            ctx.db["waivers"], {"project_id": project["_id"]}, subject="waivers", limit=_WAIVER_READ
        )
        return {
            "waivers": [
                {**_serialize_doc(w), "is_active": is_waiver_active(w.get("expiration_date"), now)} for w in waivers
            ],
            "waivers_total": waivers_total,
        }

    async def _tool_list_global_waivers(self, ctx: _ToolContext) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        waivers, waivers_total = await bounded_read(
            ctx.db["waivers"], {"project_id": None}, subject="global waivers", limit=_WAIVER_READ
        )
        return {
            "waivers": [
                {**_serialize_doc(w), "is_active": is_waiver_active(w.get("expiration_date"), now)} for w in waivers
            ],
            "waivers_total": waivers_total,
        }

    async def _tool_get_top_priority_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        limit = _clamp_limit(ctx.args.get("limit"), 5, maximum=MAX_FINDING_ROWS)
        head, names = await self._heads_in_scope(ctx)
        if not head:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        findings, ranking_note = await _ranked_findings(
            ctx.db, {"scan_id": {"$in": list(head.values())}, "severity": {"$in": ["CRITICAL", "HIGH"]}}, limit
        )
        trimmed = []
        for f in findings:
            slim = _serialize_finding_for_llm(f)
            slim["project_name"] = names.get(_row_project_id(f), "")
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

    async def _tool_generate_remediation_plan(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        head_scan_id = await self._head_scan_id(project, ctx.db)
        if not head_scan_id:
            return {"plan": [], "message": _ERR_NO_SCAN_DATA}

        max_steps = _clamp_limit(ctx.args.get("max_steps"), 10, maximum=MAX_PLAN_STEPS)

        findings, findings_total = await bounded_read(
            ctx.db["findings"],
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
        async for dep in ctx.db["dependencies"].find(
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

            resolved: list[dict[str, Any]] = []
            for f in g["findings"]:
                # Non-vulnerability findings carry no CVE list; label with the finding id.
                entries = (f.get("details") or {}).get("vulnerabilities") or [{}]
                resolved.extend(
                    {
                        "finding_id": f.get("finding_id"),
                        "cve_id": v.get("resolved_cve") or v.get("id") or f.get("finding_id"),
                        "severity": v.get("severity") or f.get("severity"),
                    }
                    for v in entries
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
            "findings_read": len(findings),
            "findings_total": findings_total,
            "cves_resolved": sum(s["resolves_count"] for s in steps),
            "critical_resolved": sum(s["critical_count"] for s in steps),
            "steps_without_fix": sum(1 for s in steps if not s["has_fix"]),
            "breaking_changes": sum(1 for s in steps if s["breaking_change_risk"] == "high"),
        }

        return {
            "project_id": project["_id"],
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

    async def _tool_get_auto_fixable_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        latest, names = await self._heads_in_scope(ctx)
        if not latest:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        limit = _clamp_limit(ctx.args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
        rows, ranking_note = await _ranked_findings(
            ctx.db,
            {
                "scan_id": {"$in": list(latest.values())},
                "severity": {"$in": ["CRITICAL", "HIGH"]},
                "details.fixed_version": {"$exists": True, "$ne": None},
                "waived": {"$ne": True},
            },
            limit,
        )
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

    async def _tool_suggest_waiver_for_finding(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        finding = await ctx.db["findings"].find_one(
            {"finding_id": ctx.args["finding_id"], "project_id": project["_id"]}
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

    async def _tool_compare_scans(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        scan_a_id = ctx.args.get("scan_id_a")
        scan_b_id = ctx.args.get("scan_id_b")
        if not scan_a_id or not scan_b_id:
            head_scan_id = await self._head_scan_id(project, ctx.db)
            preceding = await ScanRepository(ctx.db).get_preceding_scan(head_scan_id) if head_scan_id else None
            if not head_scan_id or not preceding:
                return {"error": _ERR_NEED_TWO_SCANS}
            scan_b_id = head_scan_id
            scan_a_id = preceding.id

        scan_a = await ctx.db["scans"].find_one({"_id": scan_a_id, "project_id": project["_id"]})
        scan_b = await ctx.db["scans"].find_one({"_id": scan_b_id, "project_id": project["_id"]})
        if not scan_a or not scan_b:
            return {"error": _ERR_SCAN_NOT_FOUND_IN_PROJECT}

        findings_response = await compute_findings_delta(
            ctx.db,
            project_id=project["_id"],
            from_scan=scan_a["_id"],
            to_scan=scan_b["_id"],
            page=1,
            page_size=int(ctx.args.get("page_size") or 50),
            change=None,
            severity=_ensure_list(ctx.args.get("severity")),
            finding_type=_ensure_list(ctx.args.get("finding_type")),
        )
        return findings_response.model_dump(mode="json")

    async def _tool_get_kev_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        latest, names = await self._heads_in_scope(ctx)
        if not latest:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        limit = _clamp_limit(ctx.args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
        rows, ranking_note = await _ranked_findings(
            ctx.db,
            {
                "scan_id": {"$in": list(latest.values())},
                "details.exploit_maturity": {"$in": list(KEV_EQUIVALENT_MATURITY)},
                "waived": {"$ne": True},
            },
            limit,
        )
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

    async def _tool_find_component_usage(self, ctx: _ToolContext) -> dict[str, Any]:
        latest, names = await self._heads_in_scope(ctx)
        if not names:
            return {"matches": [], "message": "No accessible projects"}
        latest_scan_ids = list(latest.values())
        # The caller may quote a finding's group-qualified component; the inventory
        # stores the bare artifact name, so search on that too.
        wanted = ctx.args["component_name"]
        patterns = {wanted, artifact_segment(wanted)}
        dep_query: dict[str, Any] = {
            "name": {"$in": [re.compile(re.escape(p), re.IGNORECASE) for p in patterns if p]},
            "scan_id": {"$in": latest_scan_ids},
        }
        if ctx.args.get("version"):
            dep_query["version"] = ctx.args["version"]
        rows, rows_total = await bounded_read(
            ctx.db["dependencies"],
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
        matches = [
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
            for r in rows
        ]
        return {"matches": matches, "count": len(matches), "matches_total": rows_total}

    async def _tool_get_findings_by_cve(self, ctx: _ToolContext) -> dict[str, Any]:
        cve = ctx.args["cve_id"].strip().upper()
        latest, names = await self._heads_in_scope(ctx)
        if not latest:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        rows, rows_total = await bounded_read(
            ctx.db["findings"],
            {
                "scan_id": {"$in": list(latest.values())},
                _FIELD_VULN_ID: cve,
            },
            subject=f"findings naming {cve}",
            limit=_CVE_OCCURRENCE_READ,
        )
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

    async def _tool_get_cve_details(self, ctx: _ToolContext) -> dict[str, Any]:
        cve = ctx.args["cve_id"].strip().upper()
        finding = await ctx.db["findings"].find_one({**await self._in_scope(ctx), _FIELD_VULN_ID: cve})
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

    async def _tool_get_stale_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        from datetime import datetime as _dt
        from datetime import timedelta as _td
        from datetime import timezone as _tz

        days = _clamp_limit(ctx.args.get("days_open"), 30, maximum=MAX_DAY_WINDOW)
        limit = _clamp_limit(ctx.args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
        sev_min = (ctx.args.get("severity_min") or "HIGH").upper()
        allowed_sev = [
            s
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            if _SEVERITY_RANK.get(s, 0) >= _SEVERITY_RANK.get(sev_min, 3)
        ]
        latest, names = await self._heads_in_scope(ctx)
        if not latest:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        cutoff = _dt.now(_tz.utc) - _td(days=days)
        project_ids = list(latest.keys())
        old_keys: set[tuple[str, tuple[str, str, str]]] = set()
        async for f in ctx.db["findings"].find(
            {"project_id": {"$in": project_ids}, "created_at": {"$lt": cutoff}},
            {**FINDING_IDENTITY_PROJECTION, "project_id": 1},
        ):
            project_id = f.get("project_id")
            if project_id:
                old_keys.update((project_id, identity) for identity in staleness_identities(f))
        if not old_keys:
            return {"findings": [], "message": f"No findings older than {days} days"}
        stale, ranking_note = await _ranked_findings(
            ctx.db,
            {"scan_id": {"$in": list(latest.values())}, "severity": {"$in": allowed_sev}},
            limit,
            keep=lambda f: any((_row_project_id(f), identity) in old_keys for identity in staleness_identities(f)),
        )
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

    async def _tool_get_license_violations(self, ctx: _ToolContext) -> dict[str, Any]:
        latest, names = await self._heads_in_scope(ctx)
        if not latest:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        limit = _clamp_limit(ctx.args.get("limit"), 10, maximum=MAX_FINDING_ROWS)
        rows, ranking_note = await _ranked_findings(
            ctx.db,
            {"scan_id": {"$in": list(latest.values())}, "type": "license"},
            limit,
        )
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

    async def _tool_get_expiring_waivers(self, ctx: _ToolContext) -> dict[str, Any]:
        from datetime import datetime as _dt
        from datetime import timedelta as _td
        from datetime import timezone as _tz

        days = _clamp_limit(ctx.args.get("days"), 30, maximum=MAX_DAY_WINDOW)
        now = _dt.now(_tz.utc)
        cutoff = now + _td(days=days)
        query: dict[str, Any] = {"expiration_date": {"$gte": now, "$lte": cutoff}}
        scope = await self._in_scope(ctx)
        if scope:
            query["$or"] = [scope, {"project_id": None}]
        rows, rows_total = await bounded_read(
            ctx.db["waivers"],
            query,
            subject="waivers expiring in the window",
            limit=_EXPIRING_WAIVER_READ,
            sort=[("expiration_date", 1)],
        )
        names = await self._project_names(ctx.db, list({_row_project_id(r) for r in rows}))
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

    async def _tool_get_team_risk_overview(self, ctx: _ToolContext) -> dict[str, Any]:
        team = await _gated(check_team_access(ctx.args.get("team_id", ""), ctx.user, ctx.db), _ERR_TEAM_NOT_FOUND)
        projects, projects_total = await bounded_read(
            ctx.db["projects"],
            and_filters(ctx.user_project_query, {"team_ids": team.id}),
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
        top3 = [{"project_id": pid, "project_name": name, "critical": c, "high": h} for c, h, pid, name in risky[:3]]
        return {
            "team_id": team.id,
            "team_name": team.name,
            # Totals are summed over the projects read; project_count is the team's whole
            # holding, so the two disagree exactly when the read saturated.
            "projects_summed": len(projects),
            "project_count": projects_total,
            "severity_totals": totals,
            "top_risky_projects": top3,
        }

    async def _tool_get_projects_without_recent_scan(self, ctx: _ToolContext) -> dict[str, Any]:
        from datetime import datetime as _dt
        from datetime import timedelta as _td
        from datetime import timezone as _tz

        days = _clamp_limit(ctx.args.get("days"), 14, maximum=MAX_DAY_WINDOW)
        limit = _clamp_limit(ctx.args.get("limit"), 10, maximum=MAX_SUMMARY_ROWS)
        cutoff = _dt.now(_tz.utc) - _td(days=days)
        query = {
            "$or": [
                {"last_scan_at": {"$lt": cutoff}},
                {"last_scan_at": None},
                {"last_scan_at": {"$exists": False}},
            ],
        }
        query = and_filters(query, ctx.user_project_query)
        cursor = ctx.db["projects"].find(query, {"_id": 1, "name": 1, "last_scan_at": 1}, limit=limit)
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

    async def _tool_get_callgraph(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        # The newest graph the project has, not head's: uploading one is a separate opt-in
        # CI step, so scoping to head would blank the tool out for most projects. The
        # response carries scan_id and created_at so the answer can say which build it is.
        doc = await ctx.db["callgraphs"].find_one(
            {"project_id": project["_id"]},
            _CALLGRAPH_SUMMARY_PROJECTION,
            sort=[("created_at", -1)],
        )
        return {"callgraph": _serialize_doc(doc) if doc else None}

    async def _tool_check_reachability(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        finding = await ctx.db["findings"].find_one({"_id": ctx.args["finding_id"], "project_id": project["_id"]})
        if not finding:
            return {"error": _ERR_FINDING_NOT_FOUND}
        reachability = (finding.get("details") or {}).get("reachability") or {}
        is_reachable = finding.get("reachable")
        analysis_level = finding.get("reachability_level")
        return {
            "finding_id": finding["_id"],
            "is_reachable": is_reachable,
            "status": reachability_display_tier(is_reachable, analysis_level),
            "analysis_level": analysis_level,
            "confidence_score": reachability.get("confidence_score"),
        }

    async def _tool_list_archives(self, ctx: _ToolContext) -> dict[str, Any]:
        read_all = has_permission(ctx.user.permissions, Permissions.ARCHIVE_READ_ALL)
        query = {}
        if ctx.args.get("project_id") and read_all:
            query["project_id"] = ctx.args["project_id"]
        elif ctx.args.get("project_id"):
            query["project_id"] = (await self._require_project(ctx))["_id"]
        elif not read_all:
            # Id-listed even for project:read_all: an archive outlives the project it came from.
            query["project_id"] = {"$in": await self._get_authorized_project_ids(ctx)}
        limit = _clamp_limit(ctx.args.get("limit"), 20, maximum=MAX_SUMMARY_ROWS)
        cursor = ctx.db["archive_metadata"].find(query, sort=[("archived_at", -1)], limit=limit)
        archives = await cursor.to_list(length=limit)
        return {"archives": [_serialize_doc(a) for a in archives]}

    async def _tool_get_archive_details(self, ctx: _ToolContext) -> dict[str, Any]:
        archive = await ctx.db["archive_metadata"].find_one({"_id": ctx.args["archive_id"]})
        if not archive:
            return {"error": _ERR_ARCHIVE_NOT_FOUND}
        if not has_permission(ctx.user.permissions, Permissions.ARCHIVE_READ_ALL):
            await self._require_project(ctx, archive.get("project_id") or "", refusal=_ERR_ARCHIVE_NOT_FOUND)
        return {"archive": _serialize_doc(archive)}

    async def _tool_list_project_webhooks(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        await _gated(check_webhook_list_permission(project["_id"], ctx.user, ctx.db), _ERR_PROJECT_NOT_FOUND)
        # Every hook that fires for the project's events: its own, its owning teams', the global ones.
        scopes: list[dict[str, Any]] = [{"project_id": project["_id"]}]
        for team_id in project.get("team_ids") or []:
            try:
                await check_team_webhook_list_permission(team_id, ctx.user, ctx.db)
            except HTTPException:
                continue
            scopes.append({"team_id": team_id})
        if has_permission(ctx.user.permissions, Permissions.SYSTEM_MANAGE):
            scopes.append({"project_id": None, "team_id": None})
        webhooks, webhooks_total = await bounded_read(
            ctx.db["webhooks"], {"$or": scopes}, subject="webhooks", limit=_WEBHOOK_READ
        )
        return {
            "webhooks": [
                {
                    **_serialize_doc(w, _WEBHOOK_FIELDS),
                    "scope": "project" if w.get("project_id") else "team" if w.get("team_id") else "global",
                }
                for w in webhooks
            ],
            "webhooks_total": webhooks_total,
        }

    async def _tool_get_webhook_deliveries(self, ctx: _ToolContext) -> dict[str, Any]:
        doc = await ctx.db["webhooks"].find_one({"_id": ctx.args.get("webhook_id")})
        try:
            webhook = Webhook.model_validate(doc)
        except ValidationError:
            # Absent, or a stored hook the model rejects, which never fires; the error would quote its secret.
            return {"error": _ERR_WEBHOOK_NOT_FOUND}
        if webhook.project_id:
            await self._require_project(ctx, webhook.project_id, refusal=_ERR_WEBHOOK_NOT_FOUND)
        await _gated(
            check_webhook_permission(webhook, ctx.user, ctx.db, Permissions.WEBHOOK_READ), _ERR_WEBHOOK_NOT_FOUND
        )
        deliveries, deliveries_total = await bounded_read(
            ctx.db["webhook_deliveries"],
            {"webhook_id": webhook.id},
            subject="webhook deliveries",
            limit=_WEBHOOK_DELIVERY_READ,
            sort=[("timestamp", -1)],
        )
        return {
            "deliveries": [_serialize_doc(d) for d in deliveries],
            "deliveries_total": deliveries_total,
        }

    async def _tool_get_system_settings(self, ctx: _ToolContext) -> dict[str, Any]:
        doc = await ctx.db["system_settings"].find_one({"_id": "current"})
        return {"settings": SystemSettingsResponse.model_validate(doc).model_dump(mode="json") if doc else {}}

    async def _tool_get_system_health(self, ctx: _ToolContext) -> dict[str, Any]:
        from app.core.cache import cache_service

        cache_health = await cache_service.health_check()
        return {"database": "connected", "cache": cache_health}

    async def _tool_list_crypto_assets(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        scan_id, build = await self._scan_under_answer(ctx, project)
        assets = await list_crypto_assets(
            ctx.db,
            project_id=project["_id"],
            scan_id=scan_id,
            asset_type=ctx.args.get("asset_type"),
            primitive=ctx.args.get("primitive"),
            name_search=ctx.args.get("name_search"),
            skip=int(ctx.args.get("skip") or 0),
            limit=_clamp_limit(ctx.args.get("limit"), 100, MAX_CRYPTO_ASSET_PAGE),
        )
        return {**assets, "scan": build}

    async def _tool_get_crypto_asset_details(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        result = await get_crypto_asset_details(ctx.db, project_id=project["_id"], asset_id=ctx.args["asset_id"])
        return result if result is not None else {"error": "Crypto asset not found"}

    async def _tool_get_crypto_summary(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        scan_id, build = await self._scan_under_answer(ctx, project)
        summary = await get_crypto_summary(ctx.db, project_id=project["_id"], scan_id=scan_id)
        return {**summary, "scan": build}

    async def _tool_get_project_crypto_policy(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        return await get_project_crypto_policy(ctx.db, project_id=project["_id"])

    async def _tool_suggest_crypto_policy_override(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        scan_id, build = await self._scan_under_answer(ctx, project)
        advice = await suggest_crypto_policy_override(ctx.db, project_id=project["_id"], scan_id=scan_id)
        return {**advice, "scan": build}

    async def _tool_get_crypto_hotspots(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        return await get_crypto_hotspots(
            ctx.db,
            project_id=project["_id"],
            group_by=ctx.args.get("group_by", "name"),
            limit=_clamp_limit(ctx.args.get("limit"), 20, MAX_CRYPTO_HOTSPOT_PAGE),
        )

    async def _tool_get_crypto_trends(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        return await get_crypto_trends(
            ctx.db,
            project_id=project["_id"],
            metric=ctx.args.get("metric", "total_crypto_findings"),
            days=int(ctx.args.get("days") or 30),
        )

    async def _tool_get_scan_delta(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        scan_a = await ctx.db["scans"].find_one({"_id": ctx.args["from_scan_id"], "project_id": project["_id"]})
        scan_b = await ctx.db["scans"].find_one({"_id": ctx.args["to_scan_id"], "project_id": project["_id"]})
        if not scan_a or not scan_b:
            return {"error": _ERR_SCAN_NOT_FOUND_IN_PROJECT}
        crypto_response = await compute_crypto_delta_envelope(
            ctx.db,
            project_id=project["_id"],
            from_scan=scan_a["_id"],
            to_scan=scan_b["_id"],
            page=1,
            page_size=int(ctx.args.get("page_size") or 50),
            change=None,
        )
        return crypto_response.model_dump(mode="json")

    async def _tool_generate_pqc_migration_plan(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        return await generate_pqc_migration_plan(
            ctx.db,
            project_id=project["_id"],
            limit=_clamp_limit(ctx.args.get("limit"), 500, MAX_PQC_PLAN_ITEMS),
        )

    async def _tool_list_compliance_reports(self, ctx: _ToolContext) -> dict[str, Any]:
        project_id = ctx.args.get("project_id")
        if project_id:
            project = await self._require_project(ctx)
            visibility: dict[str, Any] = {"scope": "project", "scope_id": project["_id"]}
        else:
            visibility = await report_visibility_filter(ctx.db, ctx.user)
        return await list_compliance_reports(
            ctx.db,
            visibility=visibility,
            framework=ctx.args.get("framework"),
            limit=_clamp_limit(ctx.args.get("limit"), 10, MAX_COMPLIANCE_REPORT_PAGE),
        )

    async def _tool_list_policy_audit_entries(self, ctx: _ToolContext) -> dict[str, Any]:
        project_id = ctx.args.get("project_id")
        # System-scope audit is admin-only (system:manage).
        if ctx.args.get("policy_scope") == "system":
            if not has_permission(ctx.user.permissions, Permissions.SYSTEM_MANAGE):
                return {"error": _ERR_ACCESS_DENIED}
        elif project_id:
            project_id = (await self._require_project(ctx))["_id"]
        return await list_policy_audit_entries(
            ctx.db,
            policy_scope=ctx.args["policy_scope"],
            project_id=project_id,
            limit=_clamp_limit(ctx.args.get("limit"), 20, MAX_POLICY_AUDIT_PAGE),
        )

    async def _tool_get_framework_evaluation_summary(self, ctx: _ToolContext) -> dict[str, Any]:
        scope = ctx.args["scope"]
        scope_id = ctx.args.get("scope_id")
        if scope == "project" and scope_id:
            scope_id = (await self._require_project(ctx, scope_id))["_id"]
        return await get_framework_evaluation_summary(
            ctx.db,
            user=ctx.user,
            scope=scope,
            scope_id=scope_id,
            framework=ctx.args["framework"],
        )

    _HANDLERS: ClassVar[dict[str, _ToolHandler]] = {
        "list_projects": _tool_list_projects,
        "get_project_details": _tool_get_project_details,
        "get_project_members": _tool_get_project_members,
        "get_project_settings": _tool_get_project_settings,
        "get_scan_history": _tool_get_scan_history,
        "get_scan_details": _tool_get_scan_details,
        "get_scan_findings": _tool_get_scan_findings,
        "get_project_findings": _tool_get_project_findings,
        "get_vulnerability_details": _tool_get_vulnerability_details,
        "search_findings": _tool_search_findings,
        "get_findings_by_severity": _tool_get_findings_by_severity,
        "get_findings_by_type": _tool_get_findings_by_type,
        "get_analytics_summary": _tool_get_analytics_summary,
        "get_risk_trends": _tool_get_risk_trends,
        "get_dependency_tree": _tool_get_dependency_tree,
        "get_hotspots": _tool_get_hotspots,
        "get_dependency_details": _tool_get_dependency_details,
        "list_teams": _tool_list_teams,
        "get_team_details": _tool_get_team_details,
        "get_team_projects": _tool_get_team_projects,
        "get_waiver_status": _tool_get_waiver_status,
        "list_project_waivers": _tool_list_project_waivers,
        "list_global_waivers": _tool_list_global_waivers,
        "get_top_priority_findings": _tool_get_top_priority_findings,
        "generate_remediation_plan": _tool_generate_remediation_plan,
        "get_auto_fixable_findings": _tool_get_auto_fixable_findings,
        "suggest_waiver_for_finding": _tool_suggest_waiver_for_finding,
        "compare_scans": _tool_compare_scans,
        "get_kev_findings": _tool_get_kev_findings,
        "find_component_usage": _tool_find_component_usage,
        "get_findings_by_cve": _tool_get_findings_by_cve,
        "get_cve_details": _tool_get_cve_details,
        "get_stale_findings": _tool_get_stale_findings,
        "get_license_violations": _tool_get_license_violations,
        "get_expiring_waivers": _tool_get_expiring_waivers,
        "get_team_risk_overview": _tool_get_team_risk_overview,
        "get_projects_without_recent_scan": _tool_get_projects_without_recent_scan,
        "get_callgraph": _tool_get_callgraph,
        "check_reachability": _tool_check_reachability,
        "list_archives": _tool_list_archives,
        "get_archive_details": _tool_get_archive_details,
        "list_project_webhooks": _tool_list_project_webhooks,
        "get_webhook_deliveries": _tool_get_webhook_deliveries,
        "get_system_settings": _tool_get_system_settings,
        "get_system_health": _tool_get_system_health,
        "list_crypto_assets": _tool_list_crypto_assets,
        "get_crypto_asset_details": _tool_get_crypto_asset_details,
        "get_crypto_summary": _tool_get_crypto_summary,
        "get_project_crypto_policy": _tool_get_project_crypto_policy,
        "suggest_crypto_policy_override": _tool_suggest_crypto_policy_override,
        "get_crypto_hotspots": _tool_get_crypto_hotspots,
        "get_crypto_trends": _tool_get_crypto_trends,
        "get_scan_delta": _tool_get_scan_delta,
        "generate_pqc_migration_plan": _tool_generate_pqc_migration_plan,
        "list_compliance_reports": _tool_list_compliance_reports,
        "list_policy_audit_entries": _tool_list_policy_audit_entries,
        "get_framework_evaluation_summary": _tool_get_framework_evaluation_summary,
    }

    async def _require_project(
        self, ctx: _ToolContext, project_id: str | None = None, *, refusal: str = _ERR_PROJECT_NOT_FOUND
    ) -> dict[str, Any]:
        """The project (the `project_id` argument unless one is named) if the caller's visibility query admits it."""
        wanted = ctx.args.get("project_id") if project_id is None else project_id
        project: dict[str, Any] | None = await ctx.db["projects"].find_one(
            and_filters({"_id": wanted}, ctx.user_project_query)
        )
        if not project:
            raise _ToolRefusal(refusal)
        return project

    async def _get_authorized_project_ids(self, ctx: _ToolContext) -> list[str]:
        return [p.id for p in await read_scope_projects(ctx.db, ctx.user_project_query)]

    async def _in_scope(self, ctx: _ToolContext) -> dict[str, Any]:
        """A `project_id` filter to the caller's projects; none for a caller who reads them all, as project
        deletion takes the project's scans, findings and waivers with it."""
        return {"project_id": {"$in": await self._get_authorized_project_ids(ctx)}} if ctx.user_project_query else {}

    async def _head_scan_id(self, project: dict[str, Any], db: AsyncIOMotorDatabase) -> str | None:
        """The scan representing the head of a project the caller already read and authorised."""
        return await ScanRepository(db).get_latest_active_scan_id(project)

    async def _scan_under_answer(self, ctx: _ToolContext, project: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """The build a scan-scoped tool answers about, with the block that names it. No scan_id means
        head; a caller that names one gets it, labelled against head, because a relayed answer carries
        no chart beside it against which a reader could notice the wrong build."""
        requested = ctx.args.get("scan_id")
        head_scan_id = await self._head_scan_id(project, ctx.db)
        wanted = requested or head_scan_id
        doc = (
            await ctx.db["scans"].find_one({"_id": wanted, "project_id": project["_id"]}, _BUILD_PROJECTION)
            if wanted
            else None
        )
        if not doc:
            # A named scan the project does not have is a bad argument; an absent one means nothing built yet.
            raise _ToolRefusal(_ERR_SCAN_NOT_FOUND_IN_PROJECT if requested else _ERR_NO_SCAN_DATA)
        scan_id: str = doc["_id"]
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

    async def _heads_in_scope(self, ctx: _ToolContext) -> tuple[dict[str, str], dict[str, str]]:
        """{project_id: head scan id} and {project_id: name} for the `project_id` argument's project, or
        for every project in the caller's scope from one read."""
        from app.services.releases import resolve_scan_ids

        if ctx.args.get("project_id"):
            project = await self._require_project(ctx)
            scan_id = await self._head_scan_id(project, ctx.db)
            return ({project["_id"]: scan_id} if scan_id else {}), {project["_id"]: project.get("name", "")}
        projects = await read_scope_projects(ctx.db, ctx.user_project_query)
        heads = await resolve_scan_ids(ctx.db, [p.id for p in projects], projects=projects)
        return heads, {p.id: p.name for p in projects}

    @staticmethod
    async def _project_names(db: AsyncIOMotorDatabase, project_ids: list[str]) -> dict[str, str]:
        cleaned = [pid for pid in project_ids if pid]
        if not cleaned:
            return {}
        names: dict[str, str] = {}
        async for p in db["projects"].find({"_id": {"$in": cleaned}}, {"name": 1}):
            names[p["_id"]] = p.get("name", "")
        return names
