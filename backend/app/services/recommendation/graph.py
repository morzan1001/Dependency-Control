from typing import Dict, List

from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.core.constants import SIMILAR_PACKAGE_GROUPS
from app.services.recommendation.common import get_attr, ModelOrDict


def analyze_deep_dependency_chains(
    dependencies: List[ModelOrDict], max_dependency_depth: int = 8
) -> List[Recommendation]:
    """Identify dependencies with very deep transitive chains, and detect cycles."""
    if not dependencies:
        return []

    recommendations = []

    depth_map: Dict[str, int] = {}
    in_cycle: set = set()

    children_map: Dict[str, List[str]] = {}
    for dep in dependencies:
        key = get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"
        parents = get_attr(dep, "parent_components", [])
        for parent in parents:
            if parent not in children_map:
                children_map[parent] = []
            children_map[parent].append(key)

    # DFS coloring: 0=unseen, 1=on stack, 2=done.
    color: Dict[str, int] = {}

    def has_cycle(node: str, path: List[str], on_path: set) -> bool:
        if node in on_path:
            # Only nodes from the first occurrence of node onward are in the cycle.
            start = path.index(node)
            in_cycle.update(path[start:])
            return True
        if color.get(node, 0) == 2:
            return False

        color[node] = 1
        path.append(node)
        on_path.add(node)

        for child in children_map.get(node, []):
            has_cycle(child, path, on_path)

        path.pop()
        on_path.discard(node)
        color[node] = 2
        return False

    for dep in dependencies:
        key = get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"
        if get_attr(dep, "direct", False) and color.get(key, 0) == 0:
            has_cycle(key, [], set())

    for dep in dependencies:
        key = get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"
        if get_attr(dep, "direct", False):
            depth_map[key] = 1

    # Skip nodes in cycles to avoid infinite loops.
    for _ in range(10):
        changed = False
        for dep in dependencies:
            key = get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"
            parents = get_attr(dep, "parent_components", [])

            if key in depth_map or key in in_cycle:
                continue

            parent_depths = []
            for parent in parents:
                if parent in depth_map and parent not in in_cycle:
                    parent_depths.append(depth_map[parent])

            if parent_depths:
                depth_map[key] = max(parent_depths) + 1
                changed = True

        if not changed:
            break

    if in_cycle:
        cycle_packages = []
        for dep in dependencies:
            key = get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"
            if key in in_cycle:
                cycle_packages.append({"name": get_attr(dep, "name"), "version": get_attr(dep, "version")})

        if cycle_packages:
            recommendations.append(
                Recommendation(
                    type=RecommendationType.DEEP_DEPENDENCY_CHAIN,
                    priority=Priority.MEDIUM,
                    title=f"Circular dependencies detected ({len(cycle_packages)} packages)",
                    description=(
                        "Circular dependencies were detected in your dependency graph. "
                        "This can cause issues with builds, updates, and increases complexity."
                    ),
                    impact={
                        "critical": 0,
                        "high": 0,
                        "medium": len(cycle_packages),
                        "low": 0,
                        "total": len(cycle_packages),
                    },
                    affected_components=[f"{p['name']}@{p['version']}" for p in cycle_packages[:10]],
                    action={
                        "type": "resolve_circular_deps",
                        "suggestions": [
                            "Review the dependency graph to identify the cycle",
                            "Consider restructuring to break the circular dependency",
                            "Check if updated versions resolve the cycle",
                        ],
                    },
                    effort="high",
                )
            )

    deep_deps = []
    for dep in dependencies:
        key = get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"
        depth = depth_map.get(key, 0)

        if depth > max_dependency_depth:
            deep_deps.append(
                {
                    "name": get_attr(dep, "name"),
                    "version": get_attr(dep, "version"),
                    "depth": depth,
                    "parents": get_attr(dep, "parent_components", [])[:3],
                }
            )

    if deep_deps:
        deep_deps.sort(key=lambda x: x["depth"], reverse=True)
        max_depth = deep_deps[0]["depth"] if deep_deps else 0

        recommendations.append(
            Recommendation(
                type=RecommendationType.DEEP_DEPENDENCY_CHAIN,
                priority=Priority.LOW,
                title=f"Deep dependency chains detected (max depth: {max_depth})",
                description=(
                    f"{len(deep_deps)} dependencies are nested more than "
                    f"{max_dependency_depth} levels deep. Deep chains increase "
                    "supply chain attack surface and make dependency updates "
                    "more complex."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": len([d for d in deep_deps if d["depth"] > 7]),
                    "low": len([d for d in deep_deps if d["depth"] <= 7]),
                    "total": len(deep_deps),
                },
                affected_components=[f"{d['name']}@{d['version']} (depth: {d['depth']})" for d in deep_deps[:10]],
                action={
                    "type": "reduce_chain_depth",
                    "suggestions": [
                        "Consider using packages with fewer transitive dependencies",
                        "Evaluate if some functionality can be implemented directly",
                        "Look for alternative packages with shallower dependency trees",
                    ],
                    "deepest_chains": [
                        {
                            "package": d["name"],
                            "depth": d["depth"],
                            "chain_preview": " → ".join(d["parents"][:3]),
                        }
                        for d in deep_deps[:5]
                    ],
                },
                effort="high",
            )
        )

    return recommendations


def analyze_duplicate_packages(
    dependencies: List[ModelOrDict],
) -> List[Recommendation]:
    """Detect packages that likely provide similar/duplicate functionality."""
    if not dependencies:
        return []

    recommendations = []

    dep_names = {str(get_attr(dep, "name", "")).lower() for dep in dependencies}

    duplicates_found = []
    for group in SIMILAR_PACKAGE_GROUPS:
        matches = [p for p in group["packages"] if p.lower() in dep_names]
        if len(matches) >= 2:
            duplicates_found.append(
                {
                    "category": group["category"],
                    "found": matches,
                    "suggestion": group["suggestion"],
                }
            )

    if duplicates_found:
        recommendations.append(
            Recommendation(
                type=RecommendationType.DUPLICATE_FUNCTIONALITY,
                priority=Priority.LOW,
                title=f"Potential duplicate packages in {len(duplicates_found)} categories",
                description=(
                    "Multiple packages providing similar functionality were detected. "
                    "Consolidating to one package per category can reduce bundle size "
                    "and maintenance burden."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": len(duplicates_found),
                    "total": len(duplicates_found),
                },
                affected_components=[f"{d['category']}: {', '.join(d['found'])}" for d in duplicates_found],
                action={
                    "type": "consolidate_packages",
                    "duplicates": duplicates_found,
                },
                effort="medium",
            )
        )

    return recommendations
