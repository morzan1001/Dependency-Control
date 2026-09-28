from typing import Any

from app.core.constants import SIMILAR_PACKAGE_GROUPS
from app.core.purl import dependency_node_key
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.recommendation.common import ModelOrDict, get_attr, sample_components

# Chains detailed in the action, and parents previewed per chain; each is paired with the
# population it was taken from.
_DEEPEST_CHAINS_SAMPLED = 5
_PARENTS_SAMPLED = 3

_KeyedDependencies = list[tuple[str, ModelOrDict]]


def analyze_deep_dependency_chains(
    dependencies: list[ModelOrDict], max_dependency_depth: int = 8
) -> list[Recommendation]:
    """Identify dependencies with very deep transitive chains, and detect cycles."""
    if not dependencies:
        return []

    keyed = [
        (dependency_node_key(get_attr(dep, "purl"), get_attr(dep, "name"), get_attr(dep, "version")), dep)
        for dep in dependencies
    ]
    recommendations = []
    in_cycle = _find_cycle_members(keyed, _children_by_parent(keyed))
    depth_map = _resolve_depths(keyed, in_cycle)

    if in_cycle:
        recommendations.append(_circular_dependency_recommendation(keyed, in_cycle))

    deep_deps = _deep_dependencies(keyed, depth_map, max_dependency_depth)
    if deep_deps:
        recommendations.append(_deep_chain_recommendation(deep_deps, max_dependency_depth))

    return recommendations


def _children_by_parent(keyed: _KeyedDependencies) -> dict[str, list[str]]:
    children_map: dict[str, list[str]] = {}
    for key, dep in keyed:
        for parent in get_attr(dep, "parent_components", []):
            children_map.setdefault(parent, []).append(key)
    return children_map


def _find_cycle_members(keyed: _KeyedDependencies, children_map: dict[str, list[str]]) -> set[str]:
    in_cycle: set[str] = set()
    # DFS coloring: 0=unseen, 1=on stack, 2=done.
    color: dict[str, int] = {}

    def visit(node: str, path: list[str], on_path: set[str]) -> None:
        if node in on_path:
            # Only nodes from the first occurrence of node onward are in the cycle.
            start = path.index(node)
            in_cycle.update(path[start:])
            return
        if color.get(node, 0) == 2:
            return

        color[node] = 1
        path.append(node)
        on_path.add(node)

        for child in children_map.get(node, []):
            visit(child, path, on_path)

        path.pop()
        on_path.discard(node)
        color[node] = 2

    for key, dep in keyed:
        if get_attr(dep, "direct", False) and color.get(key, 0) == 0:
            visit(key, [], set())
    return in_cycle


def _resolve_depths(keyed: _KeyedDependencies, in_cycle: set[str]) -> dict[str, int]:
    depth_map = {key: 1 for key, dep in keyed if get_attr(dep, "direct", False)}

    # Skip nodes in cycles to avoid infinite loops.
    for _ in range(10):
        changed = False
        for key, dep in keyed:
            if key in depth_map or key in in_cycle:
                continue

            parents = get_attr(dep, "parent_components", [])
            parent_depths = [depth_map[parent] for parent in parents if parent in depth_map and parent not in in_cycle]

            if parent_depths:
                depth_map[key] = max(parent_depths) + 1
                changed = True

        if not changed:
            break
    return depth_map


def _circular_dependency_recommendation(keyed: _KeyedDependencies, in_cycle: set[str]) -> Recommendation:
    cycle_packages = [
        {"name": get_attr(dep, "name"), "version": get_attr(dep, "version")} for key, dep in keyed if key in in_cycle
    ]
    cycle_shown, cycle_total = sample_components(f"{p['name']}@{p['version']}" for p in cycle_packages)
    return Recommendation(
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
        affected_components=cycle_shown,
        affected_components_total=cycle_total,
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


def _deep_dependencies(
    keyed: _KeyedDependencies, depth_map: dict[str, int], max_dependency_depth: int
) -> list[dict[str, Any]]:
    deep_deps = []
    for key, dep in keyed:
        depth = depth_map.get(key, 0)
        if depth > max_dependency_depth:
            deep_deps.append(
                {
                    "name": get_attr(dep, "name"),
                    "version": get_attr(dep, "version"),
                    "depth": depth,
                    "parents": get_attr(dep, "parent_components", []) or [],
                }
            )
    deep_deps.sort(key=lambda x: x["depth"], reverse=True)
    return deep_deps


def _deep_chain_recommendation(deep_deps: list[dict[str, Any]], max_dependency_depth: int) -> Recommendation:
    deep_shown, deep_total = sample_components(f"{d['name']}@{d['version']} (depth: {d['depth']})" for d in deep_deps)
    return Recommendation(
        type=RecommendationType.DEEP_DEPENDENCY_CHAIN,
        priority=Priority.LOW,
        title=f"Deep dependency chains detected (max depth: {deep_deps[0]['depth']})",
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
        affected_components=deep_shown,
        affected_components_total=deep_total,
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
                    "chain_preview": " → ".join(d["parents"][:_PARENTS_SAMPLED]),
                    "parents_total": len(d["parents"]),
                }
                for d in deep_deps[:_DEEPEST_CHAINS_SAMPLED]
            ],
            "deepest_chains_total": len(deep_deps),
        },
        effort="high",
    )


def analyze_duplicate_packages(
    dependencies: list[ModelOrDict],
) -> list[Recommendation]:
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
