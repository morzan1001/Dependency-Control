"""Loader for the IANA TLS cipher-suite catalog: shared-cache read of the live registry, bundled YAML fallback."""

from __future__ import annotations

import csv
import logging
import re
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any

import yaml

from app.core.cache import cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.models.finding import Severity

logger = logging.getLogger(__name__)

# Bump whenever _parse_components or _derive_weaknesses change: findings and compliance reports stamp it.
IANA_WEAKNESS_RULES_VERSION = 2

_CATALOG_FALLBACK_PATH = Path(__file__).parent / "iana_tls_cipher_suites.yaml"
_IANA_CSV_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
_IANA_CSV_TIMEOUT = 15.0
_IANA_CACHE_KEY = "iana:tls_cipher_suites"
_IANA_CACHE_TTL_SECONDS = 7 * 24 * 3600
# The registry lists ~350 suites; a 200 with far fewer is a proxy page or a changed format.
_MIN_REGISTRY_SUITES = 100

_SUITE_PATTERN = re.compile(r"^TLS_")

_CIPHER_KEYWORDS = {
    "RC4": "weak-cipher-rc4",
    "DES_CBC": "weak-cipher-des",
    "DES40": "weak-cipher-des",
    "3DES": "weak-cipher-3des",
    "IDEA": "weak-cipher-idea",
    "NULL": "weak-cipher-null",
    "EXPORT": "weak-cipher-export",
}

# RFC 9150 suites that authenticate but do not encrypt.
_INTEGRITY_ONLY_SUITES = frozenset({"TLS_SHA256_SHA256", "TLS_SHA384_SHA384"})

WEAKNESS_SEVERITY = {
    "null-cipher": Severity.CRITICAL,
    "null-auth": Severity.CRITICAL,
    "export-grade": Severity.CRITICAL,
    "anonymous": Severity.CRITICAL,
    "weak-kex-anon": Severity.CRITICAL,
    "weak-cipher-null": Severity.CRITICAL,
    "weak-cipher-export": Severity.CRITICAL,
    "weak-cipher-rc4": Severity.HIGH,
    "weak-cipher-des": Severity.HIGH,
    "weak-cipher-3des": Severity.HIGH,
    "weak-cipher-idea": Severity.HIGH,
    "weak-mac-md5": Severity.HIGH,
    "weak-mac-sha1": Severity.MEDIUM,
    "no-forward-secrecy": Severity.LOW,
}


@dataclass(frozen=True)
class CipherSuiteEntry:
    name: str
    value: str
    key_exchange: str
    authentication: str
    cipher: str
    mac: str
    weaknesses: list[str] = field(default_factory=list)


async def load_iana_catalog() -> dict[str, CipherSuiteEntry]:
    """The registry's suites graded by the current rules, or the bundled snapshot while the registry is unreachable."""
    raw = await cache_service.get_or_fetch_with_lock(_IANA_CACHE_KEY, _fetch_from_iana, _IANA_CACHE_TTL_SECONDS)
    if not isinstance(raw, list) or not raw:
        logger.info("IANA catalog: registry unavailable, using the bundled snapshot at %s", _CATALOG_FALLBACK_PATH)
        raw = _load_fallback_yaml()
    return _materialize(raw)


async def _fetch_from_iana() -> list[dict[str, str]] | None:
    """The registry's (name, value) rows; None when it is unreachable or answers with something else."""
    try:
        async with InstrumentedAsyncClient("IANA registry", timeout=_IANA_CSV_TIMEOUT) as client:
            resp = await client.get(_IANA_CSV_URL)
        resp.raise_for_status()
        suites = _parse_iana_csv(resp.text)
    except Exception:
        logger.exception("IANA catalog: live fetch failed (non-fatal)")
        return None
    if len(suites) < _MIN_REGISTRY_SUITES:
        logger.warning("IANA catalog: registry CSV yielded %d TLS_ suites; ignoring", len(suites))
        return None
    return suites


def _parse_iana_csv(csv_text: str) -> list[dict[str, str]]:
    reader = csv.DictReader(StringIO(csv_text))
    out: list[dict[str, str]] = []
    for row in reader:
        name = (row.get("Description") or "").strip()
        value = (row.get("Value") or "").strip()
        if not _SUITE_PATTERN.match(name):
            continue
        if "Reserved" in (row.get("Recommended", "") + row.get("Description", "")):
            continue
        out.append({"name": name, "value": value})
    return out


def _parse_components(name: str) -> dict[str, str]:
    result = {"key_exchange": "", "authentication": "", "cipher": "", "mac": ""}
    if "_WITH_" not in name:
        parts = name.split("_")
        if len(parts) >= 3:
            result["cipher"] = "NULL" if name in _INTEGRITY_ONLY_SUITES else "_".join(parts[1:-1])
            result["mac"] = parts[-1]
        return result
    lhs, rhs = name.split("_WITH_", 1)
    kex_auth = lhs.replace("TLS_", "", 1)
    if "_" in kex_auth:
        kx, _, auth = kex_auth.partition("_")
        result["key_exchange"] = kx
        result["authentication"] = auth or kx
    else:
        result["key_exchange"] = kex_auth
        result["authentication"] = kex_auth
    if "_" in rhs:
        cipher, _, mac = rhs.rpartition("_")
        result["cipher"] = cipher
        result["mac"] = mac
    else:
        result["cipher"] = rhs
    return result


def _derive_weaknesses(name: str) -> list[str]:
    tags: list[str] = []
    upper = name.upper()

    for kw, tag in _CIPHER_KEYWORDS.items():
        if kw in upper:
            tags.append(tag)

    if upper.endswith("_MD5"):
        tags.append("weak-mac-md5")
    elif upper.endswith("_SHA") and "SHA256" not in upper and "SHA384" not in upper:
        tags.append("weak-mac-sha1")

    if "anon" in name or "ANON" in upper:
        tags.append("weak-kex-anon")
        tags.append("anonymous")

    after_with = upper.split("_WITH_", 1)[-1] if "_WITH_" in upper else upper
    before_with = upper.split("_WITH_", 1)[0] if "_WITH_" in upper else ""
    if "NULL" in after_with:
        tags.append("null-cipher")
    if "NULL" in before_with:
        tags.append("null-auth")
    if upper in _INTEGRITY_ONLY_SUITES:
        tags += ["null-cipher", "weak-cipher-null"]

    if "EXPORT" in upper:
        tags.append("export-grade")

    if not any(kex in upper for kex in ("ECDHE", "DHE", "ECCPWD")) and "_WITH_" in upper:
        tags.append("no-forward-secrecy")

    return sorted(set(tags))


def _load_fallback_yaml() -> list[dict[str, Any]]:
    with _CATALOG_FALLBACK_PATH.open() as fh:
        doc = yaml.safe_load(fh) or {}
    return list(doc.get("suites") or [])


def _materialize(suites: list[dict[str, Any]]) -> dict[str, CipherSuiteEntry]:
    return {
        row["name"]: CipherSuiteEntry(
            name=row["name"],
            value=row["value"],
            weaknesses=_derive_weaknesses(row["name"]),
            **_parse_components(row["name"]),
        )
        for row in suites
    }
