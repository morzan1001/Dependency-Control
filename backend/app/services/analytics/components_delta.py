from __future__ import annotations

from typing import Dict, Tuple
from urllib.parse import unquote


def component_identity_key(comp: Dict) -> Tuple[str, str]:
    """Component identity for cross-scan matching.

    Strips version from purl so that a version bump appears as
    ``version_changed`` instead of added+removed.
    """
    purl = comp.get("purl")
    if purl and purl.startswith("pkg:"):
        # pkg:<type>/<namespace>/<name>@<version>?qualifiers#subpath
        body = purl[4:].split("@", 1)[0]  # drop version
        body = body.split("?", 1)[0].split("#", 1)[0]
        segments = body.split("/")
        if len(segments) == 1:
            return (segments[0], "")
        ptype = segments[0]
        name = unquote(segments[-1])
        namespace = "/".join(unquote(s) for s in segments[1:-1])
        type_key = f"{ptype}:{namespace}" if namespace else ptype
        return (type_key, name)

    return (comp.get("type") or "unknown", comp.get("name") or "")
