from collections import deque
from dataclasses import dataclass

from app.core.constants import DEEP_CHAIN_MEDIUM_IMPACT_DEPTH, MAX_DEPENDENCY_DEPTH, SIMILAR_PACKAGE_GROUPS
from app.core.purl import dependency_node_key, package_identity
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.recommendation.common import ModelOrDict, dependency_label, get_attr, sample_components

# Chains detailed in the action; paired with the population it was taken from.
_DEEPEST_CHAINS_SAMPLED = 5


@dataclass(frozen=True)
class DependencyEdges:
    """A dependency list as a graph over node keys; documents sharing a key are one node."""

    # First document per key, in first-seen order.
    dep_by_key: dict[str, ModelOrDict]
    parents_by_key: dict[str, list[str]]
    children_by_parent: dict[str, list[str]]
    direct_keys: set[str]


def build_dependency_edges(dependencies: list[ModelOrDict]) -> DependencyEdges:
    """Merge every document's parents per node key; a node is direct when any of its documents is."""
    dep_by_key: dict[str, ModelOrDict] = {}
    parents_by_key: dict[str, dict[str, None]] = {}
    direct_keys: set[str] = set()
    for dep in dependencies:
        key = dependency_node_key(get_attr(dep, "purl"), get_attr(dep, "name"), get_attr(dep, "version"))
        dep_by_key.setdefault(key, dep)
        parents_by_key.setdefault(key, {}).update(dict.fromkeys(get_attr(dep, "parent_components") or []))
        if get_attr(dep, "direct", False):
            direct_keys.add(key)

    children_by_parent: dict[str, dict[str, None]] = {}
    for key, parents in parents_by_key.items():
        for parent in parents:
            children_by_parent.setdefault(parent, {})[key] = None
    return DependencyEdges(
        dep_by_key=dep_by_key,
        parents_by_key={key: list(parents) for key, parents in parents_by_key.items()},
        children_by_parent={parent: list(children) for parent, children in children_by_parent.items()},
        direct_keys=direct_keys,
    )


def analyze_deep_dependency_chains(
    dependencies: list[ModelOrDict], max_dependency_depth: int = MAX_DEPENDENCY_DEPTH
) -> list[Recommendation]:
    """Report dependency cycles, and dependencies nested deeper than ``max_dependency_depth``."""
    edges = build_dependency_edges(dependencies)
    recommendations = []

    members = _cycle_members(edges)
    if members:
        recommendations.append(_circular_dependency_recommendation(members, edges))

    depths, via = _shortest_depths(edges)
    deep = sorted(
        ((key, depth) for key, depth in depths.items() if depth > max_dependency_depth), key=lambda kd: -kd[1]
    )
    if deep:
        recommendations.append(_deep_chain_recommendation(deep, via, edges, max_dependency_depth))

    return recommendations


def _cycle_members(edges: DependencyEdges) -> set[str]:
    """Nodes of every strongly connected component larger than one node, plus self-parents (Kosaraju)."""
    finished: list[str] = []
    seen: set[str] = set()
    for start in edges.dep_by_key:
        if start in seen:
            continue
        seen.add(start)
        stack = [(start, iter(edges.children_by_parent.get(start, [])))]
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                finished.append(node)
                stack.pop()
            elif child not in seen:
                seen.add(child)
                stack.append((child, iter(edges.children_by_parent.get(child, []))))

    members: set[str] = set()
    assigned: set[str] = set()
    for start in reversed(finished):
        if start in assigned:
            continue
        assigned.add(start)
        component, pending = [start], [start]
        while pending:
            # A parent that is not itself a dependency has no parents, so it closes no cycle.
            for parent in edges.parents_by_key[pending.pop()]:
                if parent in edges.dep_by_key and parent not in assigned:
                    assigned.add(parent)
                    component.append(parent)
                    pending.append(parent)
        if len(component) > 1 or start in edges.parents_by_key[start]:
            members.update(component)
    return members


def _shortest_depths(edges: DependencyEdges) -> tuple[dict[str, int], dict[str, str]]:
    """Each reachable node's shortest nesting below a direct dependency (which is depth 1), and the
    parent that shortest chain runs through."""
    depths = {key: 1 for key in edges.dep_by_key if key in edges.direct_keys}
    via: dict[str, str] = {}
    queue = deque(depths)
    while queue:
        node = queue.popleft()
        for child in edges.children_by_parent.get(node, []):
            if child not in depths:
                depths[child] = depths[node] + 1
                via[child] = node
                queue.append(child)
    return depths, via


def _circular_dependency_recommendation(members: set[str], edges: DependencyEdges) -> Recommendation:
    cycle_shown, cycle_total = sample_components(
        dependency_label(dep) for key, dep in edges.dep_by_key.items() if key in members
    )
    return Recommendation(
        type=RecommendationType.DEEP_DEPENDENCY_CHAIN,
        priority=Priority.MEDIUM,
        title=f"Circular dependencies detected ({cycle_total} packages)",
        description=(
            "Circular dependencies were detected in your dependency graph. "
            "This can cause issues with builds, updates, and increases complexity."
        ),
        impact={
            "critical": 0,
            "high": 0,
            "medium": cycle_total,
            "low": 0,
            "total": cycle_total,
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


def _chain_preview(key: str, via: dict[str, str], edges: DependencyEdges) -> str:
    """The shortest chain from a direct dependency down to ``key``."""
    path = [key]
    while path[-1] in via:
        path.append(via[path[-1]])
    return " → ".join(dependency_label(edges.dep_by_key[node]) for node in reversed(path))


def _deep_chain_recommendation(
    deep: list[tuple[str, int]], via: dict[str, str], edges: DependencyEdges, max_dependency_depth: int
) -> Recommendation:
    deep_shown, deep_total = sample_components(
        f"{dependency_label(edges.dep_by_key[key])} (depth: {depth})" for key, depth in deep
    )
    medium = sum(1 for _, depth in deep if depth >= DEEP_CHAIN_MEDIUM_IMPACT_DEPTH)
    return Recommendation(
        type=RecommendationType.DEEP_DEPENDENCY_CHAIN,
        priority=Priority.LOW,
        title=f"Deep dependency chains detected (max depth: {deep[0][1]})",
        description=(
            f"{len(deep)} dependencies are nested more than {max_dependency_depth} levels deep, "
            "even along their shortest chain from a direct dependency. Deep chains increase "
            "supply chain attack surface and make dependency updates more complex."
        ),
        impact={
            "critical": 0,
            "high": 0,
            "medium": medium,
            "low": len(deep) - medium,
            "total": len(deep),
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
                    "package": get_attr(edges.dep_by_key[key], "name"),
                    "depth": depth,
                    "chain_preview": _chain_preview(key, via, edges),
                }
                for key, depth in deep[:_DEEPEST_CHAINS_SAMPLED]
            ],
            "deepest_chains_total": len(deep),
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

    dep_names = {
        package_identity(get_attr(dep, "purl"), get_attr(dep, "name"), get_attr(dep, "type"))[1] for dep in dependencies
    }

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
