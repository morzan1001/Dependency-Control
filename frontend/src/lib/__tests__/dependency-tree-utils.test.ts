import { describe, it, expect } from 'vitest'
import { flattenUniqueDependencies } from '@/lib/dependency-tree-utils'
import type { DependencyTreeNode } from '@/types/analytics'

function node(
  id: string,
  overrides: Partial<DependencyTreeNode> = {},
): DependencyTreeNode {
  return {
    id,
    name: id,
    version: '1.0.0',
    purl: `pkg:pypi/${id}@1.0.0`,
    type: 'pypi',
    direct: false,
    has_findings: false,
    findings_count: 0,
    children: [],
    ...overrides,
  }
}

describe('flattenUniqueDependencies', () => {
  it('returns an empty array for undefined input', () => {
    expect(flattenUniqueDependencies(undefined)).toEqual([])
  })

  it('includes nested children, not just top-level nodes', () => {
    const tree = [
      node('a', { direct: true, children: [node('b', { children: [node('c')] })] }),
    ]

    const flat = flattenUniqueDependencies(tree)

    expect(flat.map(n => n.id).sort()).toEqual(['a', 'b', 'c'])
  })

  it('counts a dependency nested under several parents only once', () => {
    const shared = node('shared')
    const tree = [
      node('a', { direct: true, children: [shared] }),
      node('b', { direct: true, children: [shared] }),
    ]

    const flat = flattenUniqueDependencies(tree)

    expect(flat.filter(n => n.id === 'shared')).toHaveLength(1)
    expect(flat).toHaveLength(3)
  })

  it('supports counting direct vs transitive across the whole tree', () => {
    const tree = [
      node('a', { direct: true, children: [node('t1'), node('t2')] }),
      node('t3'),
    ]

    const flat = flattenUniqueDependencies(tree)

    expect(flat.filter(n => n.direct)).toHaveLength(1)
    expect(flat.filter(n => !n.direct)).toHaveLength(3)
  })
})
