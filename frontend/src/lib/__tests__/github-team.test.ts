import { describe, it, expect } from 'vitest'

import { githubBindingSummary, githubTeamCandidatesNote, githubTeamOptionLabel } from '@/lib/github-team'
import type { Team } from '@/types/team'

function team(binding: Partial<Team>): Team {
  return {
    id: 't-1',
    name: 'Payments Guild',
    members: [],
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...binding,
  }
}

describe('githubTeamCandidatesNote', () => {
  it('says a rule decided when several teams matched', () => {
    expect(githubTeamCandidatesNote(3, 'GitHub Team: acme/payments')).toBe(
      '3 teams matched, using GitHub Team: acme/payments'
    )
  })

  it('renders nothing for an unambiguous match', () => {
    expect(githubTeamCandidatesNote(1, 'GitHub Team: acme/payments')).toBeNull()
  })

  it('renders nothing when no team matched', () => {
    expect(githubTeamCandidatesNote(0, undefined)).toBeNull()
  })

  it('renders nothing when the project predates the field', () => {
    expect(githubTeamCandidatesNote(undefined, 'GitHub Team: acme/payments')).toBeNull()
    expect(githubTeamCandidatesNote(null, 'GitHub Team: acme/payments')).toBeNull()
  })

  it('still reports the ambiguity when the team name is not loaded yet', () => {
    expect(githubTeamCandidatesNote(2, undefined)).toBe('2 teams matched')
  })
})

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

describe('githubBindingSummary', () => {
  it('reports the organisation and the number the binding points at', () => {
    expect(
      githubBindingSummary(team({ github_org: 'Acme', github_team_slug: 'payments', github_team_id: 4711 }))
    ).toBe('Acme/payments (#4711)')
  })

  it('renders nothing for a team no repository resolves to', () => {
    expect(githubBindingSummary(team({}))).toBeNull()
    expect(githubBindingSummary(team({ github_org: 'Acme' }))).toBeNull()
  })

  it('still reports a binding whose slug was never written', () => {
    expect(githubBindingSummary(team({ github_org: 'Acme', github_team_id: 4711 }))).toBe('Acme/? (#4711)')
  })
})
