"""Stateless helpers for chat tool registry and crypto/compliance tool wrappers."""

from contextvars import ContextVar
from operator import itemgetter
from typing import Any

from app.core.config import settings
from app.core.constants import DETAILS_KEY_IN_KEV, DETAILS_KEY_KEV_RANSOMWARE, get_severity_value
from app.core.cve import advisory_ids, canonical_cve
from app.core.risk_scoring import calculate_exploit_maturity
from app.repositories.base import find_window
from app.services.recommendation.common import live_cves, vuln_info


MAX_TOOL_RESULT_BYTES = 8_000  # Cap JSON size returned to the LLM per call.

# How a bounded answer names the population its list was cut from: "<list key><suffix>".
_TOTAL_SUFFIX = "_total"

# Ceilings on an LLM-supplied limit, one per row shape; each tool's schema declares the one it uses.
# MAX_TOOL_RESULT_BYTES is what finally cuts a list — a serialized finding runs to ~850 bytes, so
# roughly nine fill the budget — and _truncate_if_too_large says so when it does. These bound
# what a call may cost before reaching that point.
MAX_FINDING_ROWS = 25
MAX_SUMMARY_ROWS = 50
MAX_PLAN_STEPS = 25
MAX_DAY_WINDOW = 365

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

_FINDING_DETAILS_FIELDS = (
    "fixed_version",
    "epss_score",
    "epss_percentile",
    "exploit_maturity",
    "risk_score",
    DETAILS_KEY_IN_KEV,
)

# A row's compact view of each advisory, and how many it lists, its primary first.
_ROW_ADVISORY_FIELDS = ("id", "severity", DETAILS_KEY_IN_KEV, "epss_score", "fixed_version", "waived")
_ROW_ADVISORIES = 3


# Clamps applied while one tool call runs, so the answer can say it was not the one asked for.
_CLAMPED_LIMITS: ContextVar[list[tuple[int, int]] | None] = ContextVar("chat_tool_clamped_limits", default=None)

# Reads that hit their ceiling while one tool call runs. An LLM relaying a list has no chart
# beside it against which a reader could notice that the list stops short.
_BOUNDED_READS: ContextVar[list[tuple[str, int, int]] | None] = ContextVar("chat_tool_bounded_reads", default=None)


def begin_limit_ledger() -> None:
    """Start recording clamps and saturated reads for one tool call."""
    _CLAMPED_LIMITS.set([])
    _BOUNDED_READS.set([])


async def bounded_read(
    collection: Any,
    query: dict[str, Any],
    *,
    subject: str,
    limit: int,
    **find_kwargs: Any,
) -> tuple[list[dict[str, Any]], int]:
    """The first `limit` rows matching `query`, and how many rows match in total.

    A truncated read is recorded so the answer says so even where the caller never named a limit.
    """
    rows, total = await find_window(collection, query, limit, **find_kwargs)
    ledger = _BOUNDED_READS.get()
    if ledger is not None and total > len(rows):
        ledger.append((subject, len(rows), total))
    return rows, total


def bounded_read_note() -> str | None:
    """What this call read against what it was answering about, or None when the two agree."""
    reads = _BOUNDED_READS.get()
    if not reads:
        return None
    pairs = "; ".join(f"{shown} of {total} {subject}" for subject, shown, total in reads)
    return (
        f"State this caveat in your answer: it covers only part of what was asked about ({pairs}). "
        "Narrow the question — a single project, a shorter window — for an answer over all of it."
    )


def clamped_limit_note() -> str | None:
    """What this call asked for against what it was given, or None when the two agree."""
    clamps = _CLAMPED_LIMITS.get()
    if not clamps:
        return None
    pairs = ", ".join(f"{requested} to {granted}" for requested, granted in clamps)
    return (
        f"A numeric argument was outside this tool's range and was changed ({pairs}). "
        "The answer covers the reduced amount; narrow the filter to see the rest."
    )


def _clamp_limit(raw: Any, default: int, maximum: int) -> int:
    """Coerce LLM-supplied `limit` to a safe integer, clamped to [1, maximum].

    A clamp is recorded, because a caller that asked for 500 and received 200 otherwise
    reads the answer as the whole of what it asked about.
    """
    try:
        requested = int(raw) if raw is not None else None
    except (TypeError, ValueError):
        requested = None
    value = default if requested is None else requested
    clamped = max(1, min(value, maximum))
    ledger = _CLAMPED_LIMITS.get()
    if requested is not None and clamped != requested and ledger is not None:
        ledger.append((requested, clamped))
    return clamped


def _ensure_list(value: Any) -> list[Any] | None:
    """Coerce an LLM-supplied scalar to a single-element list for Mongo ``$in`` queries."""
    if value is None:
        return None
    if isinstance(value, list):
        return value
    return [value] if value else None


def _clip_value(value: Any) -> Any:
    """Trim long strings/lists that blow up the LLM context."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, str) and len(value) > 400:
        return value[:400] + "…"
    if isinstance(value, list) and len(value) > 5:
        return [*value[:5], "…"]
    return value


def _number(value: Any) -> float:
    """A sort key for a stored number; missing or non-numeric sorts last."""
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else -1.0


def ranked_advisories(details: Any, first: str | None = None) -> list[dict[str, Any]]:
    """Advisories, the row's namesake first: known as `first`, live, KEV (ransomware first), severity, EPSS, CVSS."""
    entries = (details.get("vulnerabilities") or []) if isinstance(details, dict) else []
    return sorted(
        entries,
        key=lambda v: (
            first in advisory_ids(v),
            not v.get("waived"),
            bool(v.get(DETAILS_KEY_IN_KEV)),
            bool(v.get(DETAILS_KEY_KEV_RANSOMWARE)),
            get_severity_value(v.get("severity")),
            _number(v.get("epss_score")),
            _number(v.get("cvss_score")),
        ),
        reverse=True,
    )


def advisory_view(entry: dict[str, Any], *, references: int) -> dict[str, Any]:
    """One advisory's own values; a finding's details hold maxima over all its advisories and never stand in."""
    return {
        "id": canonical_cve(entry),
        "severity": entry.get("severity"),
        "cvss_score": entry.get("cvss_score"),
        "cvss_vector": entry.get("cvss_vector"),
        "epss_score": entry.get("epss_score"),
        "epss_percentile": entry.get("epss_percentile"),
        DETAILS_KEY_IN_KEV: bool(entry.get(DETAILS_KEY_IN_KEV)),
        "fixed_version": entry.get("fixed_version"),
        "waived": bool(entry.get("waived")),
        "description": _clip_value(entry.get("description") or ""),
        "references": (entry.get("references") or [])[:references],
        "scanners": entry.get("scanners"),
    }


def _live_threat(doc: dict[str, Any]) -> dict[str, Any]:
    """A vulnerability row's details fields over its unwaived advisories; the stored roll-up counts waived ones."""
    vuln = vuln_info(doc)
    top_epss = max(
        (a for a in vuln.advisories if a.get("epss_score") is not None), key=itemgetter("epss_score"), default={}
    )
    maturity = calculate_exploit_maturity(vuln.is_kev, vuln.kev_ransomware, vuln.epss_score)
    return {
        "fixed_version": vuln.fixed_version,
        "epss_score": vuln.epss_score,
        "epss_percentile": top_epss.get("epss_percentile"),
        "exploit_maturity": None if maturity == "unknown" else maturity,
        "risk_score": vuln.risk_score,
        DETAILS_KEY_IN_KEV: vuln.is_kev or None,
    }


def _serialize_finding_for_llm(doc: dict[str, Any], *, cve: str | None = None) -> dict[str, Any]:
    """Compact LLM projection: `details` flattened, the row named after its primary advisory (see ranked_advisories)."""
    if not doc:
        return {}
    out: dict[str, Any] = {}
    for key in _FINDING_TOPLEVEL_FIELDS:
        if doc.get(key) is not None:
            out[key] = _clip_value(doc[key])
    out["id"] = str(doc.get("_id", doc.get("id", "")))

    details = doc.get("details") or {}
    values = _live_threat(doc) if details.get("vulnerabilities") else details
    for key in _FINDING_DETAILS_FIELDS:
        if values.get(key) is not None:
            out[key] = _clip_value(values[key])

    advisories = ranked_advisories(details, first=cve)
    if not advisories:
        return out
    primary = advisories[0]
    if primary_id := canonical_cve(primary):
        out["cve"] = primary_id
    if primary.get("cvss_score") is not None:
        out["cvss_score"] = primary["cvss_score"]
    if refs := primary.get("references"):
        out["references"] = refs[:3]
    out["cve_count"] = len(live_cves([details]))
    if len(advisories) > 1:
        # The row-level EPSS and exploit_maturity above are maxima over live advisories; these name their holder.
        views = (advisory_view(v, references=0) for v in advisories[:_ROW_ADVISORIES])
        out["advisories"] = [{k: view[k] for k in _ROW_ADVISORY_FIELDS} for view in views]
    return out


def _parse_major(version: str | None) -> int | None:
    if not version or not isinstance(version, str):
        return None
    cleaned = version.lstrip("vV=^~ ").strip()
    head = cleaned.split(".", 1)[0].split("-", 1)[0].split("+", 1)[0]
    try:
        return int(head)
    except (TypeError, ValueError):
        return None


def _breaking_risk(current: str | None, target: str | None) -> str:
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
    """Set a 'url' deep-link on any dict in the result tree, most-specific id path wins."""
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


def _truncate_if_too_large(result: dict[str, Any]) -> dict[str, Any]:
    """Truncate the largest list in `result` so its JSON stays under MAX_TOOL_RESULT_BYTES."""
    import json as _json

    try:
        encoded = _json.dumps(result, ensure_ascii=False, default=str).encode()
    except (TypeError, ValueError):
        return result
    if len(encoded) <= MAX_TOOL_RESULT_BYTES:
        return result

    biggest_key = None
    biggest_len = 0
    for k, v in result.items():
        if isinstance(v, list) and len(v) > biggest_len:
            biggest_key = k
            biggest_len = len(v)
    if biggest_key is None:
        result["_truncated"] = True
        return result

    # Binary-search for the largest prefix that fits.
    original = result[biggest_key]
    lo, hi = 0, len(original)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        result[biggest_key] = original[:mid]
        if len(_json.dumps(result, ensure_ascii=False, default=str).encode()) <= MAX_TOOL_RESULT_BYTES:
            lo = mid
        else:
            hi = mid - 1
    result[biggest_key] = original[:lo]
    result["_truncated"] = True
    # The list may already be a page of a larger set; naming its length would report the page
    # as the population the byte cap cut from.
    population = result.get(f"{biggest_key}{_TOTAL_SUFFIX}")
    result["_truncation_note"] = (
        f"Result truncated from {population if isinstance(population, int) else biggest_len} "
        f"to {lo} entries in '{biggest_key}'. "
        f"Call this tool with a smaller limit or a narrower filter for more data."
    )
    return result


def _serialize_doc(doc: dict[str, Any] | None, fields: list[str] | None = None) -> dict[str, Any]:
    """Serialize a MongoDB doc for LLM consumption (renames _id and isoformats datetimes)."""
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
