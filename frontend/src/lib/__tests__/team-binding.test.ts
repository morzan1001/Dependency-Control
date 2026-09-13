import { describe, it, expect } from 'vitest'

import {
  bindingSummary,
  githubTeamOptionLabel,
  gitlabGroupOptionLabel,
  instanceOptionLabel,
  providerInstances,
} from '@/lib/team-binding'

function instance(overrides: Partial<{ id: string; name: string; is_active: boolean; sync_teams: boolean }> = {}) {
  return { id: 'i-1', name: 'Instance', is_active: true, sync_teams: true, ...overrides }
}

describe('githubTeamOptionLabel', () => {
  it('names the parent so two nested teams of the same name are distinguishable', () => {
    expect(
      githubTeamOptionLabel({ id: 1, slug: 'cards', name: 'Cards', parent_name: 'Payments' })
    ).toBe('Cards (cards) — under Payments')
  })

  it('leaves a top-level team without a parent clause', () => {
    expect(githubTeamOptionLabel({ id: 1, slug: 'payments', name: 'Payments', parent_name: null })).toBe(
      'Payments (payments)'
    )
  })
})

describe('gitlabGroupOptionLabel', () => {
  it('names the full path so two same-named subgroups are distinguishable', () => {
    expect(gitlabGroupOptionLabel({ id: 77, full_path: 'mo/edge', name: 'Edge' })).toBe('Edge (mo/edge)')
  })
})

describe('bindingSummary', () => {
  it('reports the organisation and the number a GitHub binding points at', () => {
    expect(
      bindingSummary({
        provider: 'github',
        instance_id: 'gh-1',
        org: 'Acme',
        slug: 'payments',
        external_id: 4711,
      })
    ).toBe('Acme/payments (#4711)')
  })

  it('reports the path and the number a GitLab binding points at', () => {
    expect(
      bindingSummary({ provider: 'gitlab', instance_id: 'gl-1', path: 'mo/edge', external_id: 77 })
    ).toBe('mo/edge (#77)')
  })

  it('still reports a binding whose slug or path was never read back', () => {
    expect(
      bindingSummary({ provider: 'github', instance_id: 'gh-1', org: 'Acme', external_id: 4711 })
    ).toBe('Acme/? (#4711)')
    expect(bindingSummary({ provider: 'gitlab', instance_id: 'gl-1', external_id: 77 })).toBe('? (#77)')
  })
})

describe('providerInstances', () => {
  it('tags each instance with the provider whose binding it would take', () => {
    const merged = providerInstances([instance({ id: 'gh-1' })], [instance({ id: 'gl-1' })])

    expect(merged.map((i) => [i.id, i.provider])).toEqual([
      ['gh-1', 'github'],
      ['gl-1', 'gitlab'],
    ])
  })

  it('carries activity and team sync through, which decide whether an instance can be offered', () => {
    const [merged] = providerInstances([], [instance({ is_active: false, sync_teams: false })])

    expect(merged).toMatchObject({ is_active: false, sync_teams: false })
  })
})

describe('instanceOptionLabel', () => {
  it('names an instance that syncs teams by itself', () => {
    expect(instanceOptionLabel({ ...instance({ name: 'GitLab Corp' }), provider: 'gitlab' })).toBe(
      'GitLab Corp'
    )
  })

  it('says a binding on an instance without team sync assigns nothing', () => {
    expect(
      instanceOptionLabel({ ...instance({ name: 'GitLab Legacy', sync_teams: false }), provider: 'gitlab' })
    ).toBe('GitLab Legacy — team sync off, assigns nothing')
  })
})
