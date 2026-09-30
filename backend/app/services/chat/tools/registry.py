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

from app.api.v1.helpers.projects import authorize_waiver_read, build_user_project_query, load_project_with_members
from app.api.v1.helpers.teams import (
    check_team_access,
    enrich_team_with_usernames,
    resolve_team_names,
    team_refs,
    visible_teams_filter,
)
from app.api.v1.helpers.webhooks import (
    check_team_webhook_list_permission,
    check_webhook_list_permission,
    check_webhook_permission,
)
from app.core.constants import (
    ANALYTICS_MAX_SCOPE_PROJECTS,
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    RETENTION_ACTION_DELETE,
    SCAN_USABLE_STATUSES,
    SETTINGS_MODE_GLOBAL,
    SETTINGS_MODE_PROJECT,
    SEVERITY_ORDER,
    get_severity_value,
    max_severity,
)
from app.core.cve import advisory_id, advisory_ids, advisory_match, canonical_cve
from app.core.housekeeping import resolve_rescan_interval
from app.core.metrics import chat_tool_calls_total, chat_tool_duration_seconds
from app.core.permissions import Permissions, has_permission
from app.core.risk_scoring import (
    ACTIVELY_EXPLOITED_MATURITY,
    calculate_exploit_maturity,
    is_deprioritized_vulnerability,
    reachability_display_tier,
)
from app.models.finding import Severity
from app.models.project import Project
from app.models.user import User
from app.models.waiver import is_waiver_active
from app.models.webhook import Webhook
from app.repositories.base import and_filters
from app.repositories.findings import FindingRepository
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.repositories.teams import TeamRepository
from app.schemas.project import license_policy_from_settings
from app.schemas.system import SystemSettingsResponse
from app.schemas.webhook import WebhookResponse
from app.services.aggregation.versions import aggregate_fixed_version, parse_version_key, split_fixed_versions
from app.services.component_identity import artifact_segment, build_component_index, lookup_component
from app.services.analytics.crypto_trends import auto_bucket
from app.services.analytics.scan_delta import InvalidDeltaQuery, compute_scan_delta_dispatch
from app.services.analytics.scopes import ScopeResolutionError, ScopeTooLargeError, read_scope_projects
from app.core.purl import canonical_purl
from app.services.compliance.visibility import report_visibility_filter
from app.services.recommendation.common import live_advisories, max_advisory_cvss

from ._arguments import ToolArgumentError, checked_arguments
from ._helpers import (
    _breaking_risk,
    _clip_value,
    _ensure_list,
    _inject_urls,
    _number,
    _serialize_doc,
    _serialize_finding_for_llm,
    _truncate_if_too_large,
    advisory_view,
    begin_limit_ledger,
    bounded_read,
    bounded_read_note,
    clamped_limit_note,
    ranked_advisories,
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


def _rendered_fields(model: type[BaseModel], *, withheld: frozenset[str] = frozenset()) -> list[str]:
    """Keys a REST response model renders, read off its fields since a validation error quotes the secrets."""
    return [
        "_id" if name == "id" else name
        for name, field in model.model_fields.items()
        if not field.exclude and name not in withheld
    ]


_PROJECT_DETAIL_FIELDS = [
    "_id",
    "name",
    "team_ids",
    "default_branch",
    "deleted_branches",
    "last_scan_at",
    "created_at",
    "active_analyzers",
    "analyzer_settings",
    "enforce_notification_settings",
    "gitlab_instance_id",
    "gitlab_project_id",
    "gitlab_project_path",
    "gitlab_mr_comments_enabled",
    "github_instance_id",
    "github_repository_id",
    "github_repository_path",
    "github_pr_comments_enabled",
]
_MEMBER_FIELDS = ("user_id", "username", "role", "effective_role", "inherited_from")
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
_SEVERITY_TIERS: tuple[str, ...] = tuple(s.value for s in Severity)

_RANKING_SAMPLED = (
    "State this caveat in your answer: the {tier} tier holds {total} findings and only "
    "{cap} were read, so these are {tier} findings but not necessarily the worst {tier} ones. "
    "Narrow the question — a single project, or a finding type — for an exact answer."
)

# Scan stats and REST analytics leave waived findings out, so every chat count and priority list does too.
_ACTIVE: dict[str, Any] = {"waived": {"$ne": True}}

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
_REMEDIATION_FINDING_READ = 500
_COMPONENT_USAGE_READ = 100
_CVE_OCCURRENCE_READ = 25
_WAIVER_STATE_READ = 50
_EXPIRING_WAIVER_READ = 25
_TEAM_RISK_PROJECT_READ = 500

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


def _slim_with_project(rows: list[dict[str, Any]], names: dict[str, str]) -> list[dict[str, Any]]:
    return [{**_serialize_finding_for_llm(f), "project_name": names.get(_row_project_id(f), "")} for f in rows]


# How a dependency's directness was established. `direct` alone cannot express it: an
# inferred-direct package is direct, but ranks below a declared one when ordering fixes.
_DIRECT_CONFIDENCE_RANK = {"declared": 0, "inferred": 1, "transitive": 2}


def _direct_confidence(dep: dict[str, Any]) -> str:
    if not dep.get("direct"):
        return "transitive"
    return "inferred" if dep.get("direct_inferred") else "declared"


_BREAKING_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "unknown": 3}

_PLAN_PROJECTION = {
    **dict.fromkeys(("type", "component", "version", "severity", "finding_id", "details.fixed_version"), 1),
    **{
        f"details.vulnerabilities.{f}": 1
        for f in ("id", "aliases", "resolved_cve", "severity", "fixed_version", "waived")
    },
}


def _fix_target(fix_lists: list[str], current: str | None) -> str | None:
    """The version fixing every list on the lowest release line from `current` up, else the highest fix listed."""
    installed = parse_version_key(current or "")
    lines = split_fixed_versions(aggregate_fixed_version([{"fixed_version": fix} for fix in fix_lists], current))
    return next((line for line in lines if parse_version_key(line) >= installed), None) or max(
        (fix for fixes in fix_lists for fix in split_fixed_versions(fixes)), key=parse_version_key, default=None
    )


def _plan_step(findings: list[dict[str, Any]], dep_meta: dict[str, Any]) -> dict[str, Any]:
    """One upgrade of one installed version; an advisory counts as resolved only when it names its own fix."""
    current = findings[0].get("version") or dep_meta.get("version")
    advisories = [(f, v) for f in findings for v in live_advisories(f.get("details"))]
    # An EOL finding carries its recommended version and no advisory.
    eol_fixes = [
        f["details"]["fixed_version"] for f in findings if f.get("type") == "eol" and f["details"].get("fixed_version")
    ]
    target = _fix_target([v["fixed_version"] for _, v in advisories if v.get("fixed_version")] + eol_fixes, current)
    resolved: dict[str | None, dict[str, Any]] = {}
    for f, v in advisories:
        if target and v.get("fixed_version"):
            cve = canonical_cve(v)
            resolved.setdefault(
                cve,
                {"finding_id": f.get("finding_id"), "cve_id": cve, "severity": v.get("severity") or f.get("severity")},
            )
    unresolved = [cve for cve in dict.fromkeys(canonical_cve(v) for _, v in advisories) if cve not in resolved]
    confidence = _direct_confidence(dep_meta)
    return {
        "component": findings[0]["component"],
        "ecosystem": dep_meta.get("type"),
        "current_version": current,
        "target_version": target,
        "is_direct": confidence != "transitive",
        "direct_confidence": confidence,
        "end_of_life": any(f.get("type") == "eol" for f in findings),
        "resolves_findings": list(resolved.values()),
        "resolves_count": len(resolved),
        "critical_count": sum(1 for r in resolved.values() if r["severity"] == "CRITICAL"),
        "unresolved": unresolved,
        "unresolved_count": len(unresolved),
        "max_severity": max_severity(*(f.get("severity") for f in findings)) or "UNKNOWN",
        "breaking_change_risk": _breaking_risk(current, target) if target else "unknown",
        "has_fix": target is not None,
    }


def _plan_sort_key(step: dict[str, Any]) -> tuple[Any, ...]:
    # Resolved criticals lead so the max_steps cut drops the least urgent steps; a declared direct dependency
    # still outranks an inferred one.
    return (
        -step["critical_count"],
        not step["has_fix"],
        _DIRECT_CONFIDENCE_RANK[step["direct_confidence"]],
        _BREAKING_RISK_ORDER[step["breaking_change_risk"]],
        -step["resolves_count"],
    )


# A head finding's waiver state, with each advisory's own flag and the ids that name it.
_WAIVER_STATE_PROJECTION = {
    "component": 1,
    "version": 1,
    "waived": 1,
    "waiver_reason": 1,
    "waiver_lapsed": 1,
    "lapsed_waiver_id": 1,
    **{f"details.vulnerabilities.{field}": 1 for field in ("id", "aliases", "resolved_cve", "waived", "waiver_reason")},
}


def _waiver_state(finding: dict[str, Any], vulnerability_id: str) -> dict[str, Any]:
    """One head finding's waiver state; asked about by an advisory id, `waived` is that advisory's on this component."""
    waived_advisories = [v for v in (finding.get("details") or {}).get("vulnerabilities") or [] if v.get("waived")]
    return {
        "component": finding.get("component"),
        "version": finding.get("version"),
        "waived": bool(finding.get("waived")) or any(vulnerability_id in advisory_ids(v) for v in waived_advisories),
        "waiver_reason": finding.get("waiver_reason"),
        "lapsed": bool(finding.get("waiver_lapsed")),
        "lapsed_waiver_id": finding.get("lapsed_waiver_id"),
        "waived_advisories": [
            {"id": canonical_cve(v), "waiver_reason": v.get("waiver_reason")} for v in waived_advisories
        ],
    }


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
    db: AsyncIOMotorDatabase, query: dict[str, Any], limit: int
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
        candidates.sort(
            key=lambda f: (
                _number((f.get("details") or {}).get("epss_score")),
                _number(max_advisory_cvss(f.get("details") or {})),
            ),
            reverse=True,
        )
        out.extend(candidates[: limit - len(out)])
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
            begin_limit_ledger()
            args = checked_arguments(tool_name, arguments)
            result = await self._dispatch(tool_name, args, user, db)
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
            answer = _truncate_if_too_large(result)
            status = "rejected" if "error" in result else "success"
            return answer
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
        limit = ctx.args["limit"]
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
        system = await SystemSettingsRepository(ctx.db).get()
        if system.retention_mode == SETTINGS_MODE_GLOBAL:
            days, action, source = system.global_retention_days, system.global_retention_action, SETTINGS_MODE_GLOBAL
        else:
            days = project.get("retention_days") or 0
            action = project.get("retention_action") or RETENTION_ACTION_DELETE
            source = SETTINGS_MODE_PROJECT
        license_entry = (project.get("analyzer_settings") or {}).get("license_compliance")
        return {
            "project": {
                **_serialize_doc(project, _PROJECT_DETAIL_FIELDS),
                "retention": {"days": days, "action": action, "source": source},
                "rescan_interval_hours": resolve_rescan_interval(Project(**project), system),
                "license_policy": license_policy_from_settings(license_entry).model_dump(),
            }
        }

    async def _tool_get_project_members(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        data = await load_project_with_members(ctx.db, project["_id"])
        if data is None:
            raise _ToolRefusal(_ERR_PROJECT_NOT_FOUND)
        return {"members": [{key: m.get(key) for key in _MEMBER_FIELDS} for m in data["members"]]}

    async def _tool_get_scan_history(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        limit = ctx.args["limit"]
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
            query["severity"] = ctx.args["severity"]
        if ctx.args.get("type"):
            query["type"] = ctx.args["type"]
        limit = ctx.args["limit"]
        findings, ranking_note = await _ranked_findings(ctx.db, query, limit)
        return {
            "findings": [_serialize_finding_for_llm(f) for f in findings],
            "count": len(findings),
            "findings_total": len(findings)
            if len(findings) < limit
            else await ctx.db["findings"].count_documents(query),
            "project_name": project.get("name"),
            "scan": build,
            **({"ranking_note": ranking_note} if ranking_note else {}),
        }

    async def _tool_get_vulnerability_details(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        finding = await ctx.db["findings"].find_one({"_id": ctx.args["finding_id"], "project_id": project["_id"]})
        if not finding:
            return {"error": _ERR_FINDING_NOT_FOUND}
        slim = _serialize_finding_for_llm(finding)
        slim["project_name"] = project.get("name", "")
        advisories = ranked_advisories(finding.get("details"))
        if advisories:
            slim["advisories"] = [advisory_view(v, references=3) for v in advisories[:5]]
            slim["advisories_total"] = len(advisories)
        return {"finding": slim}

    async def _tool_search_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        search_query = ctx.args["query"]
        pattern = {"$regex": re.escape(search_query), "$options": "i"}
        query = {
            **await self._in_scope(ctx),
            "$or": [{"finding_id": pattern}, {"description": pattern}, {"component": pattern}, advisory_match(pattern)],
        }
        if ctx.args.get("severity"):
            query["severity"] = ctx.args["severity"]
        if ctx.args.get("type"):
            query["type"] = ctx.args["type"]
        findings, findings_total = await bounded_read(
            ctx.db["findings"], query, subject="matching findings", limit=ctx.args["limit"]
        )
        names = await ProjectRepository(ctx.db).names_by_ids(_row_project_id(f) for f in findings)
        return {
            "findings": _slim_with_project(findings, names),
            "count": len(findings),
            "findings_total": findings_total,
        }

    async def _head_breakdown(self, ctx: _ToolContext, field: str) -> dict[str, Any]:
        project = await self._require_project(ctx)
        head_scan_id = await self._head_scan_id(project, ctx.db)
        if not head_scan_id:
            return {"error": _ERR_NO_SCAN_DATA}
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": head_scan_id, **_ACTIVE}},
            {"$group": {"_id": f"${field}", "count": {"$sum": 1}}},
        ]
        results = await ctx.db["findings"].aggregate(pipeline).to_list(length=None)
        return {"breakdown": {r["_id"]: r["count"] for r in results}}

    async def _tool_get_findings_by_severity(self, ctx: _ToolContext) -> dict[str, Any]:
        return await self._head_breakdown(ctx, "severity")

    async def _tool_get_findings_by_type(self, ctx: _ToolContext) -> dict[str, Any]:
        return await self._head_breakdown(ctx, "type")

    async def _tool_get_analytics_summary(self, ctx: _ToolContext) -> dict[str, Any]:
        head, names = await self._heads_in_scope(ctx)
        if not names:
            return {"total_projects": 0, "total_findings": 0, "severity_breakdown": {}}
        stats_by_project = await self._head_scan_stats(ctx.db, head)
        severity_counts = await FindingRepository(ctx.db).get_severity_distribution(
            list(head.values()), finding_type=None
        )
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
            "severity_breakdown": severity_counts,
            "total_findings": sum(severity_counts.values()),
            "top_risky_projects": top3,
            "hint": (
                "If the user asked 'where should I start' or 'what is worst', "
                "name the top_risky_projects directly instead of re-emitting the "
                "severity breakdown."
            ),
        }

    async def _tool_get_risk_trends(self, ctx: _ToolContext) -> dict[str, Any]:
        window = timedelta(days=ctx.args["days"])
        bucket = auto_bucket(window)
        head, _ = await self._heads_in_scope(ctx)
        if not head:
            return {"trend": [], "message": _ERR_NO_SCAN_DATA}
        head_scans = [
            scan
            async for scan in ctx.db["scans"].find(
                {"_id": {"$in": list(head.values())}}, {"project_id": 1, "branch": 1, "original_scan_id": 1}
            )
        ]
        head_roots = [scan.get("original_scan_id") or scan["_id"] for scan in head_scans]
        severities = ("critical", "high", "medium", "low")
        pipeline: list[dict[str, Any]] = [
            {
                "$match": {
                    "$or": [{"project_id": scan["project_id"], "branch": scan.get("branch")} for scan in head_scans],
                    # A rescan is dated now over an older commit; only the head commit's own rescans count.
                    "$nor": [{"is_rescan": True, "original_scan_id": {"$nin": head_roots}}],
                    "status": {"$in": SCAN_USABLE_STATUSES},
                    "created_at": {"$gte": datetime.now(timezone.utc) - window},
                }
            },
            {"$sort": {"created_at": -1}},
            {
                "$group": {
                    "_id": {
                        "project_id": "$project_id",
                        "period": {"$dateTrunc": {"date": "$created_at", "unit": bucket}},
                    },
                    **{field: {"$first": f"$stats.{field}"} for field in (*severities, "risk_score")},
                }
            },
            {
                "$group": {
                    "_id": "$_id.period",
                    **{severity: {"$sum": f"${severity}"} for severity in severities},
                    # A 0-100 score per project; a sum across projects would leave that scale.
                    "risk_score": {"$avg": "$risk_score"},
                    "projects": {"$sum": 1},
                }
            },
            {"$sort": {"_id": -1}},
        ]
        rows = await ctx.db["scans"].aggregate(pipeline).to_list(length=None)
        return {
            "bucket": bucket,
            "trend": [
                {
                    "period": row["_id"].date().isoformat(),
                    **{key: row[key] for key in (*severities, "risk_score", "projects")},
                }
                for row in rows
            ],
        }

    async def _tool_get_dependency_tree(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        head_scan_id = await self._head_scan_id(project, ctx.db)
        if not head_scan_id:
            return {"error": _ERR_NO_SCAN_DATA}
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
        limit = ctx.args["limit"]
        head, names = await self._heads_in_scope(ctx)
        stats_by_project = await self._head_scan_stats(ctx.db, head)
        ranked = sorted(head, key=lambda pid: (-_stat(stats_by_project.get(pid), "critical"), pid))[:limit]
        hotspots = [
            {
                "project_id": pid,
                "project_name": names.get(pid, ""),
                "head_scan_id": head[pid],
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
        details = {
            "id": team.id,
            "name": team.name,
            "description": team.description,
            "members": [m.model_dump() for m in team.members],
        }
        await enrich_team_with_usernames(details, ctx.db)
        return {"team": details}

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
        wanted = ctx.args["finding_id"]
        vulnerability_id = advisory_id(wanted) or ""
        head_scan_id = await self._head_scan_id(project, ctx.db)
        findings: list[dict[str, Any]] = []
        findings_total = 0
        if head_scan_id:
            findings, findings_total = await bounded_read(
                ctx.db["findings"],
                {"scan_id": head_scan_id, "$or": [{"finding_id": wanted}, advisory_match(vulnerability_id)]},
                subject=f"findings named {wanted}",
                limit=_WAIVER_STATE_READ,
                projection=_WAIVER_STATE_PROJECTION,
            )
        if findings:
            states = [_waiver_state(f, vulnerability_id) for f in findings]
            waived_count = sum(state["waived"] for state in states)
            return {
                "waived": waived_count == findings_total,
                "waived_count": waived_count,
                "findings": states,
                "findings_total": findings_total,
                "hint": (
                    "An advisory under waived_advisories is suppressed even where its finding is not waived; "
                    "that finding's severity counts only its live advisories."
                ),
            }
        # No finding doc for this id in the head build: an existing waiver row
        # suppresses nothing, so report it as present-but-not-suppressing.
        now = datetime.now(timezone.utc)
        named = {"$or": [{"finding_id": wanted}, {"vulnerability_id": vulnerability_id}]}
        waivers = ctx.db["waivers"]
        waiver = await waivers.find_one({**named, "project_id": project["_id"]}) or await waivers.find_one(
            {**named, "project_id": None}
        )
        if not waiver:
            return {"waived": False}
        active = is_waiver_active(waiver.get("expiration_date"), now)
        serialized = {**_serialize_doc(waiver), "is_active": active}
        if active:
            return {
                "waived": False,
                "waiver_present": True,
                "suppressing": False,
                "reason": "no matching finding in the head build — finding fixed/moved or waiver dormant",
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
        limit = ctx.args["limit"]
        head, names = await self._heads_in_scope(ctx)
        if not head:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        query = {"scan_id": {"$in": list(head.values())}, "severity": {"$in": ["CRITICAL", "HIGH"]}, **_ACTIVE}
        exploited_maturity = list(ACTIVELY_EXPLOITED_MATURITY)
        exploited, exploited_note = await _ranked_findings(
            ctx.db, {**query, "details.exploit_maturity": {"$in": exploited_maturity}}, limit
        )
        rest, rest_note = await _ranked_findings(
            ctx.db, {**query, "details.exploit_maturity": {"$nin": exploited_maturity}}, limit - len(exploited)
        )
        findings = _slim_with_project(exploited + rest, names)
        ranking_note = exploited_note or rest_note
        return {
            "findings": findings,
            "count": len(findings),
            "hint": (
                "Present these to the user as a short ordered list. For each item "
                "include project_name, CVE, component@version, severity, and the "
                "fixed_version if present. Do not call further tools unless asked."
            ),
            **({"ranking_note": ranking_note} if ranking_note else {}),
        }

    async def _tool_generate_remediation_plan(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        head_scan_id = await self._head_scan_id(project, ctx.db)
        if not head_scan_id:
            return {"plan": [], "message": _ERR_NO_SCAN_DATA}

        findings, findings_total = await bounded_read(
            ctx.db["findings"],
            {
                "scan_id": head_scan_id,
                "type": {"$in": ["vulnerability", "eol"]},
                "severity": {"$in": ["CRITICAL", "HIGH"]},
                **_ACTIVE,
            },
            subject="unwaived CRITICAL/HIGH findings",
            limit=_REMEDIATION_FINDING_READ,
            projection=_PLAN_PROJECTION,
        )
        if not findings:
            return {
                "plan": [],
                "message": "No unwaived CRITICAL/HIGH findings on the head build.",
            }

        # Keyed by lowercase component name — purl would be more precise
        # but findings don't consistently carry it.
        dep_index: dict[str, dict[str, Any]] = {}
        async for dep in ctx.db["dependencies"].find(
            {"scan_id": head_scan_id},
            {"name": 1, "version": 1, "direct": 1, "direct_inferred": 1, "type": 1, "purl": 1},
        ):
            key = (dep.get("name") or "").lower()
            existing = dep_index.get(key)
            if key and (
                existing is None
                or _DIRECT_CONFIDENCE_RANK[_direct_confidence(dep)]
                < _DIRECT_CONFIDENCE_RANK[_direct_confidence(existing)]
            ):
                dep_index[key] = dep
        # Findings carry the qualified component while the inventory keeps the bare name.
        dep_index = build_component_index(dep_index)

        groups: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
        for f in findings:
            if comp := f.get("component"):
                groups.setdefault((comp.lower(), f.get("version")), []).append(f)
        steps = sorted(
            (_plan_step(group, lookup_component(dep_index, comp) or {}) for (comp, _), group in groups.items()),
            key=_plan_sort_key,
        )

        resolved = {r["cve_id"]: r["severity"] for s in steps for r in s["resolves_findings"]}
        summary = {
            "findings_read": len(findings),
            "findings_total": findings_total,
            "cves_resolved": len(resolved),
            "critical_resolved": sum(1 for severity in resolved.values() if severity == "CRITICAL"),
            "cves_unresolved": len({cve for s in steps for cve in s["unresolved"]}),
            "steps_without_fix": sum(1 for s in steps if not s["has_fix"]),
            "breaking_changes": sum(1 for s in steps if s["breaking_change_risk"] == "high"),
        }
        plan = steps[: ctx.args["max_steps"]]
        for i, step in enumerate(plan, start=1):
            step["step"] = i
            step["resolves_findings"] = step["resolves_findings"][:10]
            step["unresolved"] = step["unresolved"][:10]

        return {
            "project_id": project["_id"],
            "project_name": project.get("name"),
            "plan": plan,
            "plan_total": len(steps),
            "summary": summary,
            "hint": (
                "Present this as a numbered Markdown plan. For each step show "
                "component current_version → target_version, severity badge, "
                "resolves_count (distinct CVEs the upgrade fixes), direct/transitive, and breaking_change_risk. "
                "Group visually into 'Quick wins' (low risk) and 'Major upgrades' "
                "(high risk) if both exist. unresolved names CVEs the upgrade leaves open, and an "
                "end_of_life step moves off an end-of-life version. The summary covers all plan_total "
                "steps: when plan_total exceeds the steps shown, say the plan shows the first of them. "
                "Mention steps_without_fix separately as items that need manual investigation (no upstream patch yet)."
            ),
        }

    async def _tool_get_auto_fixable_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        head, names = await self._heads_in_scope(ctx)
        if not head:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        rows, ranking_note = await _ranked_findings(
            ctx.db,
            {
                "scan_id": {"$in": list(head.values())},
                "type": "vulnerability",
                "severity": {"$in": ["CRITICAL", "HIGH"]},
                **_ACTIVE,
                # The live_fixed_version rule: a live advisory names a fix and no live CRITICAL/HIGH one lacks one.
                "details.vulnerabilities": {"$elemMatch": {"fixed_version": {"$nin": [None, ""]}, **_ACTIVE}},
                "$nor": [
                    {
                        "details.vulnerabilities": {
                            "$elemMatch": {
                                "severity": {"$in": ["CRITICAL", "HIGH"]},
                                "fixed_version": {"$in": [None, ""]},
                                **_ACTIVE,
                            }
                        }
                    }
                ],
            },
            ctx.args["limit"],
        )
        out = []
        for slim, f in zip(_slim_with_project(rows, names), rows, strict=True):
            advisories, version = live_advisories(f.get("details")), f.get("version")
            urgent = [
                v["fixed_version"]
                for v in advisories
                if v.get("fixed_version") and v.get("severity") in ("CRITICAL", "HIGH")
            ]
            fix = _fix_target(urgent, version)
            if fix and parse_version_key(fix) > parse_version_key(version or ""):
                out.append(
                    {
                        **slim,
                        "quick_fix_version": fix,
                        "breaking_change_risk": _breaking_risk(version, fix),
                        # The bump fixes an advisory exactly when adding its fix leaves the target unchanged.
                        "still_open": [
                            canonical_cve(v)
                            for v in advisories
                            if not v.get("fixed_version") or _fix_target([*urgent, v["fixed_version"]], version) != fix
                        ],
                    }
                )
        return {
            "findings": out,
            "count": len(out),
            "hint": (
                "Upgrading to quick_fix_version fixes every CRITICAL/HIGH advisory of these findings. A row with "
                "breaking_change_risk 'high' needs a major upgrade: list it apart from the quick wins. The "
                "lower-severity advisories under still_open stay after the upgrade: call that a partial fix."
            ),
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

        if details.get(DETAILS_KEY_IN_KEV):
            return {
                "suggested_reason": (
                    "NOT RECOMMENDED TO WAIVE. This vulnerability is listed in CISA KEV — it is "
                    "actively exploited in the wild. Patch rather than waive."
                ),
                "suggested_expiry_days": 0,
                "recommend_waive": False,
            }
        tier = reachability_display_tier(finding.get("reachable"), finding.get("reachability_level"))
        deprioritized = is_deprioritized_vulnerability(
            epss_score=epss if isinstance(epss, (int, float)) else None,
            is_kev=False,
            reachable=finding.get("reachable"),
        )
        reasons = []
        if tier == "unreachable":
            reasons.append("the vulnerable code is not reachable from the project")
        elif deprioritized:
            reasons.append(f"real-world exploit likelihood is low (EPSS={epss:.4f})")
        if sev in ("LOW", "NEGLIGIBLE", "INFO"):
            reasons.append(f"severity is {sev}")
        suggested_reason = (
            "Accepted risk: " + "; ".join(reasons) + "."
            if reasons
            else "Accepted risk: insert justification here. No strong automatic signal found."
        )
        if fix:
            suggested_reason += f" Upgrade to {fix} is available: the waiver only bridges the time until it ships."
        return {
            "suggested_reason": suggested_reason,
            "suggested_expiry_days": 30 if fix else 180 if deprioritized else 90,
            "recommend_waive": bool(reasons) and tier != "confirmed" and not (fix and sev in ("CRITICAL", "HIGH")),
            "signals": {
                "severity": sev,
                "exploit_maturity": maturity,
                "epss_score": epss,
                "reachability": tier,
                "has_fix_version": bool(fix),
            },
            "hint": (
                "Show these signals to the user and let them edit the suggested reason "
                "before creating the waiver. This tool does NOT create the waiver. When recommend_waive "
                "is false (confirmed reachable, a CRITICAL/HIGH fix exists, or no signal supports the "
                "risk), advise patching instead."
            ),
        }

    async def _tool_compare_scans(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        from_id, to_id = ctx.args.get("from_scan_id"), ctx.args.get("to_scan_id")
        named = [scan_id for scan_id in (from_id, to_id) if scan_id]
        if named:
            in_project = await ctx.db["scans"].distinct("_id", {"_id": {"$in": named}, "project_id": project["_id"]})
            if any(scan_id not in in_project for scan_id in named):
                return {"error": _ERR_SCAN_NOT_FOUND_IN_PROJECT}
        # Head and a verified scan's predecessor are this project's by construction.
        to_scan = to_id or await self._head_scan_id(project, ctx.db)
        preceding = await ScanRepository(ctx.db).get_preceding_scan(to_scan) if to_scan and not from_id else None
        from_scan = from_id or (preceding.id if preceding else None)
        if not from_scan or not to_scan:
            return {"error": _ERR_NEED_TWO_SCANS}
        try:
            delta = await compute_scan_delta_dispatch(
                db=ctx.db,
                project_id=project["_id"],
                category=ctx.args.get("category") or "findings",
                from_scan=from_scan,
                to_scan=to_scan,
                page=int(ctx.args.get("page") or 1),
                page_size=ctx.args["page_size"],
                change=ctx.args.get("change"),
                severity=_ensure_list(ctx.args.get("severity")),
                finding_type=_ensure_list(ctx.args.get("finding_type")),
                allow_same_scan=not (from_id and to_id),
            )
        except InvalidDeltaQuery as e:
            return {"error": str(e)}
        return delta.model_dump(mode="json")

    async def _tool_get_kev_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        head, names = await self._heads_in_scope(ctx)
        if not head:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        rows, ranking_note = await _ranked_findings(
            ctx.db,
            {
                "scan_id": {"$in": list(head.values())},
                "details.vulnerabilities": {"$elemMatch": {DETAILS_KEY_IN_KEV: True, **_ACTIVE}},
                **_ACTIVE,
            },
            ctx.args["limit"],
        )
        out = _slim_with_project(rows, names)
        return {
            "findings": out,
            "count": len(out),
            "hint": (
                "Each has an unwaived advisory in CISA KEV, named as cve: it has real-world exploits. "
                "Prioritise above plain CVSS-only critical findings."
            ),
            **({"ranking_note": ranking_note} if ranking_note else {}),
        }

    async def _tool_find_component_usage(self, ctx: _ToolContext) -> dict[str, Any]:
        head, names = await self._heads_in_scope(ctx)
        if not names:
            return {"matches": [], "message": "No accessible projects"}
        head_scan_ids = list(head.values())
        # The caller may quote a finding's group-qualified component; the inventory
        # stores the bare artifact name, so search on that too.
        wanted = ctx.args["component_name"]
        patterns = {wanted, artifact_segment(wanted)}
        dep_query: dict[str, Any] = {
            "name": {"$in": [re.compile(re.escape(p), re.IGNORECASE) for p in patterns if p]},
            "scan_id": {"$in": head_scan_ids},
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
        cve = advisory_id(ctx.args["cve_id"]) or ""
        head, names = await self._heads_in_scope(ctx)
        if not head:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        rows, rows_total = await bounded_read(
            ctx.db["findings"],
            {
                "scan_id": {"$in": list(head.values())},
                **advisory_match(cve),
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
            slot["findings"].append(_serialize_finding_for_llm(f, cve=cve))
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
        cve = advisory_id(ctx.args["cve_id"]) or ""
        finding = await ctx.db["findings"].find_one({**await self._in_scope(ctx), **advisory_match(cve)})
        if not finding:
            return {"error": f"{cve} not found in any of your projects' scan data"}
        advisory = next(v for v in finding["details"]["vulnerabilities"] if cve in advisory_ids(v))
        in_kev = bool(advisory.get(DETAILS_KEY_IN_KEV))
        return {
            "cve_id": cve,
            **advisory_view(advisory, references=5),
            "exploit_maturity": calculate_exploit_maturity(
                in_kev, bool(advisory.get(DETAILS_KEY_KEV_RANSOMWARE)), advisory.get("epss_score")
            ),
            "affected_component": f"{finding.get('component', '')}@{finding.get('version', '')}",
        }

    async def _tool_get_stale_findings(self, ctx: _ToolContext) -> dict[str, Any]:
        days = ctx.args["days_open"]
        sev_min = (ctx.args.get("severity_min") or "HIGH").upper()
        allowed_sev = [
            s
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            if get_severity_value(s) >= SEVERITY_ORDER.get(sev_min, SEVERITY_ORDER["HIGH"])
        ]
        head, names = await self._heads_in_scope(ctx)
        if not head:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        stale, ranking_note = await _ranked_findings(
            ctx.db,
            {
                "scan_id": {"$in": list(head.values())},
                "severity": {"$in": allowed_sev},
                "first_seen_at": {"$lt": datetime.now(timezone.utc) - timedelta(days=days)},
                **_ACTIVE,
            },
            ctx.args["limit"],
        )
        out = [
            {**slim, "first_seen_at": _clip_value(f.get("first_seen_at"))}
            for slim, f in zip(_slim_with_project(stale, names), stale, strict=True)
        ]
        return {
            "findings": out,
            "count": len(out),
            "days_open_threshold": days,
            "hint": "These findings have lingered for more than the threshold. Suggest either fixing or escalating.",
            **({"ranking_note": ranking_note} if ranking_note else {}),
        }

    async def _tool_get_license_violations(self, ctx: _ToolContext) -> dict[str, Any]:
        head, names = await self._heads_in_scope(ctx)
        if not head:
            return {"findings": [], "message": _ERR_NO_SCAN_DATA}
        rows, ranking_note = await _ranked_findings(
            ctx.db, {"scan_id": {"$in": list(head.values())}, "type": "license", **_ACTIVE}, ctx.args["limit"]
        )
        out = _slim_with_project(rows, names)
        return {
            "findings": out,
            "count": len(out),
            **({"ranking_note": ranking_note} if ranking_note else {}),
        }

    async def _tool_get_expiring_waivers(self, ctx: _ToolContext) -> dict[str, Any]:
        from datetime import datetime as _dt
        from datetime import timedelta as _td
        from datetime import timezone as _tz

        days = ctx.args["days"]
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
        names = await ProjectRepository(ctx.db).names_by_ids(_row_project_id(r) for r in rows)
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

        days = ctx.args["days"]
        limit = ctx.args["limit"]
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
        limit = ctx.args["limit"]
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
        stored = await SystemSettingsRepository(ctx.db).get()
        return {"settings": SystemSettingsResponse.model_validate(stored).model_dump(mode="json")}

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
            limit=ctx.args["limit"],
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
            limit=ctx.args["limit"],
        )

    async def _tool_get_crypto_trends(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        return await get_crypto_trends(
            ctx.db,
            project_id=project["_id"],
            metric=ctx.args.get("metric", "total_crypto_findings"),
            days=ctx.args["days"],
        )

    async def _tool_generate_pqc_migration_plan(self, ctx: _ToolContext) -> dict[str, Any]:
        project = await self._require_project(ctx)
        return await generate_pqc_migration_plan(
            ctx.db,
            project_id=project["_id"],
            limit=ctx.args["limit"],
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
            limit=ctx.args["limit"],
        )

    async def _tool_list_policy_audit_entries(self, ctx: _ToolContext) -> dict[str, Any]:
        # System-scope audit is admin-only (system:manage).
        if ctx.args.get("policy_scope") == "system":
            if not has_permission(ctx.user.permissions, Permissions.SYSTEM_MANAGE):
                return {"error": _ERR_ACCESS_DENIED}
            project_id = None
        elif ctx.args.get("project_id"):
            project_id = (await self._require_project(ctx))["_id"]
        else:
            raise ToolArgumentError("project_id is required for policy_scope=project")
        return await list_policy_audit_entries(
            ctx.db,
            policy_scope=ctx.args["policy_scope"],
            project_id=project_id,
            policy_type=ctx.args["policy_type"],
            limit=ctx.args["limit"],
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
        "get_scan_history": _tool_get_scan_history,
        "get_scan_details": _tool_get_scan_details,
        "get_scan_findings": _tool_get_scan_findings,
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
        rows = await ProjectRepository(ctx.db).find_many_raw(
            ctx.user_project_query, limit=ANALYTICS_MAX_SCOPE_PROJECTS + 1, projection={"_id": 1}
        )
        if len(rows) > ANALYTICS_MAX_SCOPE_PROJECTS:
            raise ScopeTooLargeError(
                f"This scope holds more than {ANALYTICS_MAX_SCOPE_PROJECTS} projects; ask about a team or a single project."
            )
        return [row["_id"] for row in rows]

    async def _in_scope(self, ctx: _ToolContext) -> dict[str, Any]:
        """A `project_id` filter to the caller's projects; none for a caller who reads them all."""
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
        """Head scan ids and names by project id, for the `project_id` argument or the whole scope in one read."""
        from app.services.releases import resolve_scan_ids

        if ctx.args.get("project_id"):
            project = await self._require_project(ctx)
            scan_id = await self._head_scan_id(project, ctx.db)
            return ({project["_id"]: scan_id} if scan_id else {}), {project["_id"]: project.get("name", "")}
        projects = await read_scope_projects(ctx.db, ctx.user_project_query)
        heads = await resolve_scan_ids(ctx.db, [p.id for p in projects], projects=projects)
        return heads, {p.id: p.name for p in projects}
