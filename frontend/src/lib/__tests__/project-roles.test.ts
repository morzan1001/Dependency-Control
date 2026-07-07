import { describe, it, expect } from 'vitest'

import {
  getUserProjectRole,
  hasProjectRole,
  isProjectAdmin,
  isProjectEditor,
  canUpdateProject,
  canDeleteProject,
  canRotateApiKey,
  canManageProjectMembers,
  canCreateProjectWaiver,
} from '../project-roles'
import type { Project } from '@/types/project'

// Minimal Project factory; only the fields the role logic reads matter.
function makeProject(members: Array<{ user_id: string; role: string; inherited_from?: string }> = [], ownerId?: string): Project {
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
})

describe('hasProjectRole — WRITE superuser (project:update / project:delete)', () => {
  const project = makeProject()

  it('project:update satisfies any required role and bypasses membership', () => {
    const perms = ['project:update']
    expect(hasProjectRole(project, STRANGER, 'viewer', perms)).toBe(true)
    expect(hasProjectRole(project, STRANGER, 'editor', perms)).toBe(true)
    expect(hasProjectRole(project, STRANGER, 'admin', perms)).toBe(true)
    expect(isProjectAdmin(project, STRANGER, perms)).toBe(true)
    // member management gate (admin-only) must open for the write superuser
    expect(canManageProjectMembers(project, STRANGER, perms)).toBe(true)
    expect(canDeleteProject(project, STRANGER, perms)).toBe(true)
  })

  it('project:delete also satisfies the admin gate', () => {
    const perms = ['project:delete']
    expect(isProjectAdmin(project, STRANGER, perms)).toBe(true)
    expect(canDeleteProject(project, STRANGER, perms)).toBe(true)
    expect(canManageProjectMembers(project, STRANGER, perms)).toBe(true)
  })
})

describe('getUserProjectRole / role hierarchy', () => {
  it('owner beats everything', () => {
    const project = makeProject([], 'owner-1')
    expect(getUserProjectRole(project, 'owner-1')).toBe('owner')
    expect(isProjectAdmin(project, 'owner-1', [])).toBe(true)
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

  it('team-derived members are already merged into project.members by the API (team admin -> admin)', () => {
    // The backend detail endpoint merges team members into members with mapped
    // roles + inherited_from, so team admins resolve to project admin here.
    const project = makeProject([
      { user_id: 'team-admin', role: 'admin', inherited_from: 'Team: DevOps' },
    ])
    expect(getUserProjectRole(project, 'team-admin')).toBe('admin')
    expect(canManageProjectMembers(project, 'team-admin', [])).toBe(true)
  })
})
