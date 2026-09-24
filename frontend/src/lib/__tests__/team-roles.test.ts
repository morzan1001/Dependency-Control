import { describe, it, expect } from 'vitest'

import {
  hasTeamRole,
  isTeamAdmin,
  canUpdateTeam,
  canDeleteTeam,
  canManageTeamMembers,
  canManageTeamWebhooks,
} from '../team-roles'
import type { Team } from '@/types/team'

function makeTeam(members: Array<{ user_id: string; role: string }> = []): Team {
  return { id: 't1', name: 'Team', members } as Team
}

const AUDITOR = 'auditor-1'
const STRANGER = 'stranger-1'

describe('hasTeamRole — team:read_all is READ-ONLY', () => {
  const team = makeTeam([{ user_id: 'someone-else', role: 'admin' }])
  const readAll = ['team:read_all']

  it('read_all grants a member (read) request', () => {
    expect(hasTeamRole(team, AUDITOR, 'member', readAll)).toBe(true)
  })

  it('read_all does NOT grant the admin role', () => {
    expect(hasTeamRole(team, AUDITOR, 'admin', readAll)).toBe(false)
    expect(isTeamAdmin(team, AUDITOR, readAll)).toBe(false)
  })

  it('an auditor with only read_all cannot update, delete, manage members or manage webhooks', () => {
    expect(canUpdateTeam(team, AUDITOR, readAll)).toBe(false)
    expect(canDeleteTeam(team, AUDITOR, readAll)).toBe(false)
    expect(canManageTeamMembers(team, AUDITOR, readAll)).toBe(false)
    expect(canManageTeamWebhooks(team, AUDITOR, readAll)).toBe(false)
  })
})

describe('global write grants bypass membership', () => {
  const team = makeTeam()

  it('team:update opens update and member management', () => {
    expect(canUpdateTeam(team, STRANGER, ['team:update'])).toBe(true)
    expect(canManageTeamMembers(team, STRANGER, ['team:update'])).toBe(true)
  })

  it('team:delete opens delete', () => {
    expect(canDeleteTeam(team, STRANGER, ['team:delete'])).toBe(true)
  })
})

describe('team roles', () => {
  const team = makeTeam([
    { user_id: 'admin-1', role: 'admin' },
    { user_id: 'member-1', role: 'member' },
  ])

  it('an admin member satisfies every role', () => {
    expect(hasTeamRole(team, 'admin-1', 'member', [])).toBe(true)
    expect(isTeamAdmin(team, 'admin-1', [])).toBe(true)
  })

  it('a plain member satisfies member but not admin', () => {
    expect(hasTeamRole(team, 'member-1', 'member', [])).toBe(true)
    expect(isTeamAdmin(team, 'member-1', [])).toBe(false)
  })

  it('a non-member satisfies nothing', () => {
    expect(hasTeamRole(team, STRANGER, 'member', [])).toBe(false)
  })
})
