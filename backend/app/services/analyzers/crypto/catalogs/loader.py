"""
Loader for the IANA TLS cipher-suite catalog YAML.

Loaded once per-process and cached in-memory. The YAML is versioned with the
code (snapshot), not auto-updated — bump CURRENT_IANA_CATALOG_VERSION and
regenerate via backend/scripts/generate_iana_catalog.py when updating.
"""

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

import yaml

CURRENT_IANA_CATALOG_VERSION = 1

_CATALOG_PATH = Path(__file__).parent / "iana_tls_cipher_suites.yaml"


@dataclass(frozen=True)
class CipherSuiteEntry:
    name: str
    value: str
    key_exchange: str
    authentication: str
    cipher: str
    mac: str
    weaknesses: List[str] = field(default_factory=list)


@lru_cache(maxsize=1)
def load_iana_catalog() -> Dict[str, CipherSuiteEntry]:
    with _CATALOG_PATH.open() as fh:
        doc = yaml.safe_load(fh) or {}
    entries = doc.get("suites") or []
    out: Dict[str, CipherSuiteEntry] = {}
    for e in entries:
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
