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

describe('canManageTeamWebhooks — webhook:create needs membership or team:update', () => {
  const team = makeTeam([
    { user_id: 'admin-1', role: 'admin' },
    { user_id: 'member-1', role: 'member' },
  ])

  it('read_all plus webhook:create offers no webhook writes on a foreign team', () => {
    expect(canManageTeamWebhooks(team, AUDITOR, ['team:read_all', 'webhook:create'])).toBe(false)
  })

  it('webhook:create alone offers no webhook writes to a non-member', () => {
    expect(canManageTeamWebhooks(team, STRANGER, ['webhook:create'])).toBe(false)
  })

  it('a plain member writes with webhook:create but not without it', () => {
    expect(canManageTeamWebhooks(team, 'member-1', ['webhook:create'])).toBe(true)
    expect(canManageTeamWebhooks(team, 'member-1', [])).toBe(false)
  })

  it('team:update writes without membership only together with webhook:create', () => {
    expect(canManageTeamWebhooks(team, STRANGER, ['team:update', 'webhook:create'])).toBe(true)
    expect(canManageTeamWebhooks(team, STRANGER, ['team:update'])).toBe(false)
  })

  it('a team admin writes without a webhook permission', () => {
    expect(canManageTeamWebhooks(team, 'admin-1', [])).toBe(true)
  })
})
