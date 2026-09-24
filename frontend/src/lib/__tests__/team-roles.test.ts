import { describe, it, expect } from 'vitest'

import {
  hasTeamRole,
  isTeamAdmin,
  canUpdateTeam,
  canDeleteTeam,
  canManageTeamMembers,
  canCreateTeamWebhooks,
  canDeleteTeamWebhooks,
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

  it('an auditor with only read_all cannot update, delete, manage members or write webhooks', () => {
    expect(canUpdateTeam(team, AUDITOR, readAll)).toBe(false)
    expect(canDeleteTeam(team, AUDITOR, readAll)).toBe(false)
    expect(canManageTeamMembers(team, AUDITOR, readAll)).toBe(false)
    expect(canCreateTeamWebhooks(team, AUDITOR, readAll)).toBe(false)
    expect(canDeleteTeamWebhooks(team, AUDITOR, readAll)).toBe(false)
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

describe('canCreateTeamWebhooks — webhook:create needs membership or team:update', () => {
  const team = makeTeam([
    { user_id: 'admin-1', role: 'admin' },
    { user_id: 'member-1', role: 'member' },
  ])

  it('read_all plus webhook:create offers no webhook writes on a foreign team', () => {
    expect(canCreateTeamWebhooks(team, AUDITOR, ['team:read_all', 'webhook:create'])).toBe(false)
  })

  it('webhook:create alone offers no webhook writes to a non-member', () => {
    expect(canCreateTeamWebhooks(team, STRANGER, ['webhook:create'])).toBe(false)
  })

  it('a plain member writes with webhook:create but not without it', () => {
    expect(canCreateTeamWebhooks(team, 'member-1', ['webhook:create'])).toBe(true)
    expect(canCreateTeamWebhooks(team, 'member-1', [])).toBe(false)
  })

  it('team:update writes without membership only together with webhook:create', () => {
    expect(canCreateTeamWebhooks(team, STRANGER, ['team:update', 'webhook:create'])).toBe(true)
    expect(canCreateTeamWebhooks(team, STRANGER, ['team:update'])).toBe(false)
  })

  it('a team admin writes without a webhook permission', () => {
    expect(canCreateTeamWebhooks(team, 'admin-1', [])).toBe(true)
  })
})

describe('canDeleteTeamWebhooks — webhook:delete needs membership or team:update', () => {
  const team = makeTeam([
    { user_id: 'admin-1', role: 'admin' },
    { user_id: 'member-1', role: 'member' },
  ])

  it('a member with webhook:create but not webhook:delete cannot delete', () => {
    expect(canDeleteTeamWebhooks(team, 'member-1', ['webhook:create'])).toBe(false)
  })

  it('a member with webhook:delete but not webhook:create deletes and does not create', () => {
    expect(canDeleteTeamWebhooks(team, 'member-1', ['webhook:delete'])).toBe(true)
    expect(canCreateTeamWebhooks(team, 'member-1', ['webhook:delete'])).toBe(false)
  })

  it('read_all plus webhook:delete offers no delete on a foreign team', () => {
    expect(canDeleteTeamWebhooks(team, AUDITOR, ['team:read_all', 'webhook:delete'])).toBe(false)
  })

  it('webhook:delete alone offers no delete to a non-member', () => {
    expect(canDeleteTeamWebhooks(team, STRANGER, ['webhook:delete'])).toBe(false)
  })

  it('team:update deletes without membership only together with webhook:delete', () => {
    expect(canDeleteTeamWebhooks(team, STRANGER, ['team:update', 'webhook:delete'])).toBe(true)
    expect(canDeleteTeamWebhooks(team, STRANGER, ['team:update', 'webhook:create'])).toBe(false)
  })

  it('a team admin deletes without a webhook permission', () => {
    expect(canDeleteTeamWebhooks(team, 'admin-1', [])).toBe(true)
  })
})
