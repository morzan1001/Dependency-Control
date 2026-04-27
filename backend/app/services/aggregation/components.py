"""Pure component-name helpers extracted from ResultAggregator.

These are stateless string utilities used during aggregation:
  * normalize_component  - lowercase + strip
  * extract_artifact_name - reduce qualified names to a single artifact id
"""

from __future__ import annotations


def normalize_component(component: str) -> str:
    if not component:
        return "unknown"
    return component.strip().lower()


def extract_artifact_name(component: str) -> str:
    """Extract artifact name from qualified component names for grouping.

    Handles Maven-style 'org.postgresql:postgresql' → 'postgresql'
    and scoped packages '@angular/core' → 'core'.
    """
    name = component.lower().strip() if component else "unknown"
    if ":" in name:
        name = name.rsplit(":", 1)[-1]
    elif "/" in name:
        name = name.rsplit("/", 1)[-1]
    return name or "unknown"
