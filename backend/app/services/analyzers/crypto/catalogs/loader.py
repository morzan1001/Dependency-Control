"""
Loader for the IANA TLS cipher-suite catalog.

Follows the same pattern every other external-data analyzer uses
(OSV, deps.dev, EPSS, GHSA): fetch from the upstream URL on demand,
cache the parsed result in Redis, fall back to a bundled YAML
snapshot when the network is unreachable or Redis is unavailable.

Usage:
    from app.services.analyzers.crypto.catalogs.loader import (
        CipherSuiteEntry,
        CURRENT_IANA_CATALOG_VERSION,
        load_iana_catalog,
    )

    catalog = await load_iana_catalog()  # Dict[name, CipherSuiteEntry]

Update cadence: IANA publishes new cipher suites rarely (on the order
of once a year).  The Redis TTL below is one week; fresh deployments
and pods joining the cluster hit iana.org once until the first cache
populates, then reuse the shared entry.
"""

from __future__ import annotations

import asyncio
import csv
import logging
import re
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import yaml

from app.core.cache import cache_service

logger = logging.getLogger(__name__)

CURRENT_IANA_CATALOG_VERSION = 1

_CATALOG_FALLBACK_PATH = Path(__file__).parent / "iana_tls_cipher_suites.yaml"
_IANA_CSV_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
_IANA_CSV_TIMEOUT = 15.0
_IANA_CSV_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB — registry is ~200 KiB today
_IANA_CACHE_KEY = "iana:tls_cipher_suites:v1"
_IANA_CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days

_SUITE_PATTERN = re.compile(r"^TLS_")

_CIPHER_KEYWORDS = {
    "RC4": "weak-cipher-rc4",
    "DES_CBC": "weak-cipher-des",
    "DES40": "weak-cipher-des",
    "3DES": "weak-cipher-3des",
    "NULL": "weak-cipher-null",
    "EXPORT": "weak-cipher-export",
}


@dataclass(frozen=True)
class CipherSuiteEntry:
    name: str
    value: str
    key_exchange: str
    authentication: str
    cipher: str
    mac: str
    weaknesses: List[str] = field(default_factory=list)


# In-process memoization to avoid re-hitting Redis inside a hot analysis
# loop. Reset via ``reset_iana_cache_for_tests``; expires naturally when
# the pod is replaced.
_IN_PROCESS_CACHE: Optional[Dict[str, CipherSuiteEntry]] = None
_IN_PROCESS_LOCK = asyncio.Lock()


async def load_iana_catalog() -> Dict[str, CipherSuiteEntry]:
    """Return the current IANA TLS cipher-suite catalog.

    Resolution order:
      1. In-process memoized copy (fast path on the same pod).
      2. Redis cache (shared across pods, 7-day TTL).
      3. Live fetch from iana.org + Redis write-through.
      4. Bundled YAML snapshot (offline / boot-before-internet fallback).
    """
    global _IN_PROCESS_CACHE
    if _IN_PROCESS_CACHE is not None:
        return _IN_PROCESS_CACHE

    async with _IN_PROCESS_LOCK:
        if _IN_PROCESS_CACHE is not None:
            return _IN_PROCESS_CACHE

        cached_raw = await _read_from_redis()
        if cached_raw is not None:
            catalog = _materialize(cached_raw)
            _IN_PROCESS_CACHE = catalog
            return catalog

        fetched_raw = await _fetch_from_iana()
        if fetched_raw is not None:
            await _write_to_redis(fetched_raw)
            catalog = _materialize(fetched_raw)
            _IN_PROCESS_CACHE = catalog
            return catalog

        logger.warning(
            "IANA catalog: live fetch + Redis lookup both failed, falling back to bundled snapshot at %s",
            _CATALOG_FALLBACK_PATH,
        )
        fallback_raw = _load_fallback_yaml()
        catalog = _materialize(fallback_raw)
        _IN_PROCESS_CACHE = catalog
        return catalog


def reset_iana_cache_for_tests() -> None:
    """Clear the in-process memoized catalog. Tests should call this in
    teardown when they inject a patched fetch/cache."""
    global _IN_PROCESS_CACHE
    _IN_PROCESS_CACHE = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _read_from_redis() -> Optional[List[Dict[str, Any]]]:
    try:
        cached = await cache_service.get(_IANA_CACHE_KEY)
    except Exception:
        logger.exception("IANA catalog: Redis GET failed (non-fatal)")
        return None
    if not isinstance(cached, list) or not cached:
        return None
    return cached


async def _write_to_redis(suites: List[Dict[str, Any]]) -> None:
    try:
        await cache_service.set(_IANA_CACHE_KEY, suites, _IANA_CACHE_TTL_SECONDS)
    except Exception:
        logger.exception("IANA catalog: Redis SET failed (non-fatal)")


async def _fetch_from_iana() -> Optional[List[Dict[str, Any]]]:
    """Fetch the CSV from iana.org and parse into suite dicts.

    Returns None on any network / parsing error — callers use the
    bundled fallback when this happens.
    """
    try:
        async with httpx.AsyncClient(timeout=_IANA_CSV_TIMEOUT) as client:
            resp = await client.get(_IANA_CSV_URL)
            resp.raise_for_status()
            body = resp.content
            if len(body) > _IANA_CSV_MAX_BYTES:
                logger.warning(
                    "IANA catalog: registry CSV is %d bytes (> %d limit); refusing",
                    len(body),
                    _IANA_CSV_MAX_BYTES,
                )
                return None
            return _parse_iana_csv(body.decode("utf-8", errors="replace"))
    except Exception:
        logger.exception("IANA catalog: live fetch failed (non-fatal)")
        return None


def _parse_iana_csv(csv_text: str) -> List[Dict[str, Any]]:
    reader = csv.DictReader(StringIO(csv_text))
    out: List[Dict[str, Any]] = []
    for row in reader:
        name = (row.get("Description") or "").strip()
        value = (row.get("Value") or "").strip()
        if not _SUITE_PATTERN.match(name):
            continue
        if "Reserved" in (row.get("Recommended", "") + row.get("Description", "")):
            continue
        comps = _parse_components(name)
        out.append(
            {
                "name": name,
                "value": value,
                "key_exchange": comps["key_exchange"],
                "authentication": comps["authentication"],
                "cipher": comps["cipher"],
                "mac": comps["mac"],
                "weaknesses": _derive_weaknesses(name),
            }
        )
    return out


def _parse_components(name: str) -> Dict[str, str]:
    result = {"key_exchange": "", "authentication": "", "cipher": "", "mac": ""}
    if "_WITH_" not in name:
        parts = name.split("_")
        if len(parts) >= 3:
            result["cipher"] = "_".join(parts[1:-1])
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


def _derive_weaknesses(name: str) -> List[str]:
    tags: List[str] = []
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

    if "EXPORT" in upper:
        tags.append("export-grade")

    # No forward secrecy: no ephemeral exchange
    if not any(kex in upper for kex in ("ECDHE", "DHE", "ECCPWD")):
        if "_WITH_" in upper:
            tags.append("no-forward-secrecy")

    return sorted(set(tags))


def _load_fallback_yaml() -> List[Dict[str, Any]]:
    with _CATALOG_FALLBACK_PATH.open() as fh:
        doc = yaml.safe_load(fh) or {}
    return list(doc.get("suites") or [])


def _materialize(suites: List[Dict[str, Any]]) -> Dict[str, CipherSuiteEntry]:
    out: Dict[str, CipherSuiteEntry] = {}
    for e in suites:
        name = e.get("name")
        if not name:
            continue
        out[name] = CipherSuiteEntry(
            name=name,
            value=e.get("value", ""),
            key_exchange=e.get("key_exchange", ""),
            authentication=e.get("authentication", ""),
            cipher=e.get("cipher", ""),
            mac=e.get("mac", ""),
            weaknesses=list(e.get("weaknesses") or []),
        )
    return out
