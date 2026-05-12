from __future__ import annotations

import hashlib
from typing import Any, Dict, Tuple


def finding_identity_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """Stable identity for matching the 'same' finding across two scans.

    finding_id is per-scan and unusable; we derive a semantic key from
    type-specific identifier fields.
    """
    ftype = finding.get("type") or ""
    component = finding.get("component") or ""
    details = finding.get("details") or {}
    identifier: str

    if ftype == "vulnerability":
        identifier = str(details.get("cve_id") or details.get("vuln_id") or "")
    elif ftype == "secret":
        identifier = str(details.get("pattern_hash") or details.get("rule_id") or "")
    elif ftype == "sast":
        rule = str(details.get("rule_id") or "")
        line = details.get("line")
        identifier = f"{rule}:{line}" if line is not None else rule
    elif ftype == "iac":
        identifier = str(details.get("rule_id") or "")
    elif ftype == "license":
        identifier = str(details.get("license_id") or details.get("license") or "")
    elif ftype == "malware":
        identifier = str(details.get("signature") or details.get("rule_id") or "")
    elif ftype == "eol":
        identifier = str(details.get("eol_date") or details.get("version") or "")
    elif ftype == "outdated":
        identifier = str(details.get("latest_version") or "")
    else:
        identifier = ""

    if not identifier:
        # Fallback: deterministic hash of description + file_path so
        # an unidentifiable finding at least matches itself across scans
        # if its description/location is identical.
        digest_src = (
            (finding.get("description") or "")
            + "|"
            + "|".join(finding.get("found_in") or [])
        )
        identifier = hashlib.sha1(digest_src.encode("utf-8")).hexdigest()[:12]

    return (ftype, component, identifier)
