"""
One-shot generator for the IANA TLS cipher-suite catalog YAML.

Reads the authoritative IANA registry CSV and emits a normalized YAML file
that the runtime loader consumes. Run manually when bumping the catalog.

Usage:
    poetry run python backend/scripts/generate_iana_catalog.py \
        --output backend/app/services/analyzers/crypto/catalogs/iana_tls_cipher_suites.yaml

Source: https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
"""

import argparse
import csv
import datetime as dt
import re
import sys
import urllib.request
from pathlib import Path

import yaml

IANA_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
SUITE_PATTERN = re.compile(r"^TLS_")

CIPHER_KEYWORDS = {
    "RC4": "weak-cipher-rc4",
    "DES_CBC": "weak-cipher-des",
    "DES40": "weak-cipher-des",
    "3DES": "weak-cipher-3des",
    "NULL": "weak-cipher-null",
    "EXPORT": "weak-cipher-export",
}


def derive_weaknesses(name: str) -> list[str]:
    tags: list[str] = []
    upper = name.upper()

    for kw, tag in CIPHER_KEYWORDS.items():
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


def parse_components(name: str) -> dict[str, str]:
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--source-url", default=IANA_URL)
    args = ap.parse_args()

    with urllib.request.urlopen(args.source_url) as fh:
        reader = csv.DictReader(line.decode() for line in fh)
        entries = []
        for row in reader:
            name = row.get("Description", "").strip()
            value = row.get("Value", "").strip()
            if not SUITE_PATTERN.match(name):
                continue
            if "Reserved" in (row.get("Recommended", "") + row.get("Description", "")):
                continue
            comps = parse_components(name)
            entries.append({
                "name": name,
                "value": value,
                "key_exchange": comps["key_exchange"],
                "authentication": comps["authentication"],
                "cipher": comps["cipher"],
                "mac": comps["mac"],
                "weaknesses": derive_weaknesses(name),
            })

    doc = {
        "version": 1,
        "source": "IANA TLS Cipher Suite Registry",
        "source_url": args.source_url,
        "snapshot_date": dt.date.today().isoformat(),
        "suites": entries,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml.safe_dump(doc, sort_keys=False, width=120))
    print(f"Wrote {len(entries)} suites to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
