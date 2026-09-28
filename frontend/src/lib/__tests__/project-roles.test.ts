import { describe, it, expect } from 'vitest'

import {
  getUserProjectRole,
  hasProjectRole,
  isProjectAdmin,
  isProjectEditor,
  canUpdateProject,
  canBindGitLabProject,
  canDeleteProject,
  canRotateApiKey,
  canManageProjectMembers,
  canCreateProjectWaiver,
  canCreateProjectWebhook,
  canDeleteProjectWebhook,
} from '../project-roles'
import type { Project } from '@/types/project'

function makeProject(
  members: Array<{ user_id: string; role: string; inherited_from?: string; effective_role?: string }> = [],
  ownerId?: string,
): Project {
  return {
    id: 'p1',
    name: 'Proj',
    owner_id: ownerId,
    members,
  } as Project
}

const AUDITOR = 'auditor-1'
const STRANGER = 'stranger-1'

describe('hasProjectRole — project:read_all is READ-ONLY (audit #1)', () => {
  const project = makeProject([{ user_id: 'someone-else', role: 'admin' }])
  const readAll = ['project:read_all']

  it('read_all grants a viewer (read) request', () => {
    expect(hasProjectRole(project, AUDITOR, 'viewer', readAll)).toBe(true)
  })

  it('read_all does NOT grant editor (write) requests', () => {
    expect(hasProjectRole(project, AUDITOR, 'editor', readAll)).toBe(false)
  })

  it('read_all does NOT grant admin (write) requests', () => {
    expect(hasProjectRole(project, AUDITOR, 'admin', readAll)).toBe(false)
    expect(isProjectAdmin(project, AUDITOR, readAll)).toBe(false)
    expect(isProjectEditor(project, AUDITOR, readAll)).toBe(false)
  })

  it('an auditor with only read_all cannot delete / rotate / manage members', () => {
    expect(canDeleteProject(project, AUDITOR, readAll)).toBe(false)
    expect(canRotateApiKey(project, AUDITOR, readAll)).toBe(false)
    expect(canManageProjectMembers(project, AUDITOR, readAll)).toBe(false)
    expect(canUpdateProject(project, AUDITOR, readAll)).toBe(false)
    expect(canCreateProjectWaiver(project, AUDITOR, readAll)).toBe(false)
  })

  it('waiver:manage governs global waivers only; a project waiver needs an editor role', () => {
    expect(canCreateProjectWaiver(project, AUDITOR, ['waiver:manage'])).toBe(false)
  })
})

describe('hasProjectRole — WRITE superuser (project:update); project:delete deletes only', () => {
  const project = makeProject()

  it('project:update satisfies any required role and bypasses membership', () => {
    const perms = ['project:update']
    expect(hasProjectRole(project, STRANGER, 'viewer', perms)).toBe(true)
    expect(hasProjectRole(project, STRANGER, 'editor', perms)).toBe(true)
    expect(hasProjectRole(project, STRANGER, 'admin', perms)).toBe(true)
    expect(isProjectAdmin(project, STRANGER, perms)).toBe(true)
    // member management gate (admin-only) must open for the write superuser
    expect(canManageProjectMembers(project, STRANGER, perms)).toBe(true)
  })

  it('project:update does not open the deletion', () => {
    expect(canDeleteProject(project, STRANGER, ['project:update'])).toBe(false)
  })

  it('project:delete opens the deletion and nothing else', () => {
    const perms = ['project:delete']
    expect(canDeleteProject(project, STRANGER, perms)).toBe(true)
    expect(isProjectAdmin(project, STRANGER, perms)).toBe(false)
    expect(canManageProjectMembers(project, STRANGER, perms)).toBe(false)
    expect(canRotateApiKey(project, STRANGER, perms)).toBe(false)
    expect(canBindGitLabProject(perms)).toBe(false)
  })
})

describe('getUserProjectRole / role hierarchy', () => {
  it('owner beats everything', () => {
    const project = makeProject([], 'owner-1')
    expect(getUserProjectRole(project, 'owner-1')).toBe('owner')
    expect(isProjectAdmin(project, 'owner-1', [])).toBe(true)
    expect(canDeleteProject(project, 'owner-1', [])).toBe(true)
  })

  it('direct member roles resolve and respect the hierarchy', () => {
    const project = makeProject([
      { user_id: 'a', role: 'admin' },
      { user_id: 'e', role: 'editor' },
      { user_id: 'v', role: 'viewer' },
    ])
    expect(getUserProjectRole(project, 'a')).toBe('admin')
    expect(isProjectAdmin(project, 'a', [])).toBe(true)
    expect(isProjectEditor(project, 'e', [])).toBe(true)
    expect(isProjectAdmin(project, 'e', [])).toBe(false)
    expect(isProjectEditor(project, 'v', [])).toBe(false)
    expect(hasProjectRole(project, 'v', 'viewer', [])).toBe(true)
  })

  it('non-members with no global perms get nothing', () => {
    const project = makeProject([{ user_id: 'a', role: 'admin' }])
    expect(getUserProjectRole(project, STRANGER)).toBeNull()
    expect(hasProjectRole(project, STRANGER, 'viewer', [])).toBe(false)
  })

  it('a direct viewer the API reports as effective admin is gated as admin', () => {
    const project = makeProject([{ user_id: 'v', role: 'viewer', effective_role: 'admin' }])
    expect(getUserProjectRole(project, 'v')).toBe('admin')
    expect(canManageProjectMembers(project, 'v', [])).toBe(true)
    expect(canDeleteProject(project, 'v', ['project:update'])).toBe(true)
  })

  it('team-derived members are already merged into project.members by the API (team admin -> admin)', () => {
    const project = makeProject([
      { user_id: 'team-admin', role: 'admin', inherited_from: 'Team: DevOps' },
    ])
    expect(getUserProjectRole(project, 'team-admin')).toBe('admin')
    expect(canManageProjectMembers(project, 'team-admin', [])).toBe(true)
  })
})

describe('project webhook writes need membership or the global write grant', () => {
  const project = makeProject([
    { user_id: 'viewer-1', role: 'viewer' },
    { user_id: 'team-viewer', role: 'viewer', inherited_from: 'Team: DevOps' },
  ])
  const webhookWrite = ['webhook:create', 'webhook:delete']

  it('read_all plus the webhook permissions offers no webhook writes on a foreign project', () => {
    const perms = ['project:read_all', ...webhookWrite]
    expect(canCreateProjectWebhook(project, AUDITOR, perms)).toBe(false)
    expect(canDeleteProjectWebhook(project, AUDITOR, perms)).toBe(false)
  })

  it('the webhook permissions alone offer no webhook writes to a non-member', () => {
    expect(canCreateProjectWebhook(project, STRANGER, webhookWrite)).toBe(false)
    expect(canDeleteProjectWebhook(project, STRANGER, webhookWrite)).toBe(false)
  })

  it('a viewer member, direct or through a team, writes with the matching webhook permission', () => {
    for (const member of ['viewer-1', 'team-viewer']) {
      expect(canCreateProjectWebhook(project, member, ['webhook:create'])).toBe(true)
      expect(canDeleteProjectWebhook(project, member, ['webhook:create'])).toBe(false)
      expect(canDeleteProjectWebhook(project, member, ['webhook:delete'])).toBe(true)
    }
  })

  it('a viewer member without a webhook permission gets no webhook writes', () => {
    expect(canCreateProjectWebhook(project, 'viewer-1', [])).toBe(false)
    expect(canDeleteProjectWebhook(project, 'viewer-1', [])).toBe(false)
  })

  it('the global write grant writes without membership', () => {
    expect(canCreateProjectWebhook(project, STRANGER, ['project:update'])).toBe(true)
    expect(canDeleteProjectWebhook(project, STRANGER, ['project:update'])).toBe(true)
  })
})

describe('the GitLab binding follows the API: system:manage or the global write grant', () => {
  it('opens for each of those grants', () => {
    for (const grant of ['system:manage', 'project:update']) {
      expect(canBindGitLabProject([grant])).toBe(true)
    }
  })

  it('stays closed to a project creator, who administers only their own projects', () => {
    expect(canBindGitLabProject(['project:create', 'project:read'])).toBe(false)
  })
})
