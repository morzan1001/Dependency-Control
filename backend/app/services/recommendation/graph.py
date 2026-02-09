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
    """
    Identify dependencies with very deep transitive chains.
    Deep chains increase supply chain risk and make updates harder.
    Also detects circular dependencies.
    """
    if not dependencies:
        return []

    recommendations = []

    # Build a simple depth map based on parent_components
    depth_map: Dict[str, int] = {}  # purl/name -> estimated depth
    in_cycle: set = set()  # Track nodes that are part of cycles

    # Build adjacency list for cycle detection
    children_map: Dict[str, List[str]] = {}  # parent -> list of children
    for dep in dependencies:
        key = get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"
        parents = get_attr(dep, "parent_components", [])
        for parent in parents:
            if parent not in children_map:
                children_map[parent] = []
            children_map[parent].append(key)

    # Detect cycles using DFS with coloring (white=0, gray=1, black=2)
    color: Dict[str, int] = {}

    def has_cycle(node: str, path: set) -> bool:
        if node in path:
            in_cycle.update(path)
            return True
        if color.get(node, 0) == 2:  # Already fully processed
            return False

        color[node] = 1  # Mark as being processed
        path.add(node)

        for child in children_map.get(node, []):
            if has_cycle(child, path):
                in_cycle.add(node)

        path.remove(node)
        color[node] = 2  # Mark as fully processed
        return False

    # Run cycle detection from all direct dependencies
    for dep in dependencies:
        key = get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"
        if get_attr(dep, "direct", False) and color.get(key, 0) == 0:
            has_cycle(key, set())

    # First pass: direct deps have depth 1
    for dep in dependencies:
        key = get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"
        if get_attr(dep, "direct", False):
            depth_map[key] = 1

    # Iterative depth calculation (skip nodes in cycles to avoid infinite loops)
    for _ in range(10):  # Max iterations
        changed = False
        for dep in dependencies:
            key = get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"
            parents = get_attr(dep, "parent_components", [])

            if key in depth_map or key in in_cycle:
                continue

            # Calculate depth from parents (excluding those in cycles)
            parent_depths = []
            for parent in parents:
                if parent in depth_map and parent not in in_cycle:
                    parent_depths.append(depth_map[parent])

            if parent_depths:
                depth_map[key] = max(parent_depths) + 1
                changed = True

        if not changed:
            break

    # Warn about circular dependencies if any detected
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

    # Find deeply nested deps
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
        # Sort by depth
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
    """
    Detect packages that likely provide similar/duplicate functionality.
    """
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
