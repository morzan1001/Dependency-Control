"""Stateless helpers for chat tool registry and crypto/compliance tool wrappers."""

from typing import Any, Dict, List, Optional

from app.core.config import settings

MAX_TOOL_LIMIT = 200  # Hard cap on LLM-supplied limit arguments to prevent DoS.
MAX_TOOL_RESULT_BYTES = 8_000  # Cap JSON size returned to the LLM per call.

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
    """Compact LLM projection: flattens `details` and the first CVE from
    `details.vulnerabilities` so CVE ID + fix + EPSS sit at the top level."""
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
        # Surface first CVE as a concrete handle; remaining count via cve_count.
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
    if not severity:
        return "unknown"
    return severity.lower()


def _parse_major(version: Optional[str]) -> Optional[int]:
    if not version or not isinstance(version, str):
        return None
    cleaned = version.lstrip("vV=^~ ").strip()
    head = cleaned.split(".", 1)[0].split("-", 1)[0].split("+", 1)[0]
    try:
        return int(head)
    except (TypeError, ValueError):
        return None


def _compare_versions(a: str, b: str) -> int:
    """Naive numeric-tuple comparison (-1/0/1) with lexicographic fallback —
    good enough to pick the 'largest' fix_version, not a full semver."""

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
    """Walk a tool result tree and set a 'url' deep-link field on any dict that
    has enough identifiers, longest-path wins:
      - project_id + scan_id + id → scan details with finding drawer open
      - project_id + scan_id → scan details
      - project_id only → project details
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
    """Truncate the largest list in `result` so JSON stays under
    MAX_TOOL_RESULT_BYTES, preventing a single tool result from blowing the
    LLM's context window."""
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
    result["_truncation_note"] = (
        f"Result truncated from {biggest_len} to {lo} entries in '{biggest_key}'. "
        f"Call this tool with a smaller limit or a narrower filter for more data."
    )
    return result


def _serialize_doc(doc: Optional[Dict[str, Any]], fields: Optional[List[str]] = None) -> Dict[str, Any]:
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
