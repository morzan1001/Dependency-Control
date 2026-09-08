"""Stateless helpers for chat tool registry and crypto/compliance tool wrappers."""

from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.services.aggregation.components import extract_artifact_name
from app.services.analytics.findings_delta import finding_identity_key
from app.services.recommendation.common import finding_cve_ids


def _waiver_is_active(waiver: dict[str, Any], now: datetime | None = None) -> bool:
    """True if expiration_date is absent, null, or in the future; mirrors WaiverRepository._non_expired_filter."""
    expiration: datetime | None = waiver.get("expiration_date")
    if expiration is None:
        return True
    reference = now or datetime.now(timezone.utc)
    # expiration_date may be tz-naive in the DB; normalize to UTC before comparing.
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=timezone.utc)
    return bool(expiration > reference)


MAX_TOOL_RESULT_BYTES = 8_000  # Cap JSON size returned to the LLM per call.

# How a bounded answer names the population its list was cut from: "<list key><suffix>".
_TOTAL_SUFFIX = "_total"

# Ceilings on an LLM-supplied limit, one per row shape, and every tool names the one it uses.
# MAX_TOOL_RESULT_BYTES is what finally cuts a list — a serialized finding runs to ~850 bytes, so
# roughly nine fill the budget — and _truncate_if_too_large says so when it does. These bound
# what a call may cost before reaching that point.
MAX_FINDING_ROWS = 25
MAX_SUMMARY_ROWS = 50
MAX_PLAN_STEPS = 25
MAX_DAY_WINDOW = 365

# details.exploit_maturity values meaning actively exploited in the wild.
KEV_EQUIVALENT_MATURITY = ("active", "weaponized")

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
    "cvss_score",
)

_SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NEGLIGIBLE": 0,
    "INFO": 0,
    "UNKNOWN": 0,
}


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

    The count costs a round trip only once the read saturates, which is the only time the two
    can differ. A saturated read is recorded so the answer says so even where the caller never
    named a limit.
    """
    rows: list[dict[str, Any]] = await collection.find(query, limit=limit, **find_kwargs).to_list(length=limit)
    if len(rows) < limit:
        return rows, len(rows)
    total = await collection.count_documents(query)
    ledger = _BOUNDED_READS.get()
    if ledger is not None:
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


_VULNERABILITY = "vulnerability"


def staleness_identities(finding: dict[str, Any]) -> set[tuple[str, str, str]]:
    """What a finding must still be for its "days open" clock to keep running.

    A vulnerability record is keyed once per advisory on the folded component name. The scan
    delta's identity carries ``version`` on purpose — a bump is a change it must report — but
    reusing it here would restart the clock the moment an unrelated upgrade lands, and a
    long-lived unfixed advisory is the one that most deserves attention. Every other type's
    identity is already version-free, so it is taken as the delta computes it.
    """
    if (finding.get("type") or "") == _VULNERABILITY:
        component = extract_artifact_name(finding.get("component") or "")
        advisories = finding_cve_ids(finding)
        if advisories:
            return {(_VULNERABILITY, component, advisory) for advisory in advisories}
    return {finding_identity_key(finding)}


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
        return value[:5] + ["…"]
    return value


def _flatten_primary_vuln(out: dict[str, Any], vulns: list[dict[str, Any]]) -> None:
    """Mutate `out` with fields lifted from the first nested CVE."""
    if not vulns:
        return
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


def _serialize_finding_for_llm(doc: dict[str, Any]) -> dict[str, Any]:
    """Compact LLM projection: flattens `details` and the first CVE to the top level."""
    if not doc:
        return {}
    out: dict[str, Any] = {}
    for key in _FINDING_TOPLEVEL_FIELDS:
        if doc.get(key) is not None:
            out[key] = _clip_value(doc[key])
    out["id"] = str(doc.get("_id", doc.get("id", "")))

    details = doc.get("details") or {}
    for key in _FINDING_DETAILS_FIELDS:
        if details.get(key) is not None:
            out[key] = _clip_value(details[key])

    _flatten_primary_vuln(out, details.get("vulnerabilities") or [])
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


def _compare_versions(a: str, b: str) -> int:
    """Naive numeric-tuple comparison (-1/0/1) to pick the 'largest' fix_version, not full semver."""

    def parts(v: str) -> list[Any]:
        out: list[Any] = []
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
        encoded = _json.dumps(result, default=str)
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
        if len(_json.dumps(result, default=str)) <= MAX_TOOL_RESULT_BYTES:
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
