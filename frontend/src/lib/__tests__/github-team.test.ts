import { describe, it, expect } from 'vitest'

import { githubTeamCandidatesNote } from '@/lib/github-team'

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
