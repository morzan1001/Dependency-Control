import type { DependencyTreeNode } from '@/types/analytics'

/**
 * Return each dependency in the tree once, keyed by id. A package pulled in by several
 * parents is duplicated across the tree, so summary counts walk this deduplicated view
 * rather than the top-level nodes alone.
 */
export function flattenUniqueDependencies(
  nodes: DependencyTreeNode[] | undefined,
): DependencyTreeNode[] {
  const seen = new Map<string, DependencyTreeNode>()

  const walk = (list: DependencyTreeNode[]) => {
    for (const node of list) {
      if (!seen.has(node.id)) {
        seen.set(node.id, node)
      }
      if (node.children && node.children.length > 0) {
        walk(node.children)
      }
    }
  }

  walk(nodes ?? [])
  return Array.from(seen.values())
}
