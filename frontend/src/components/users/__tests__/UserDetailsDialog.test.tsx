import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'

import { UserDetailsDialog } from '../UserDetailsDialog'
import type { User } from '@/types/user'

interface ProjectStub {
  id: string
  name: string
  members?: { user_id: string }[]
  team_ids?: string[]
  teams?: { id: string; name: string }[]
}

// useProjects returns only the first 100 projects; useProjectsDropdown pages the full list.
const targetUserId = 'user-target'
const firstPage: ProjectStub[] = Array.from({ length: 100 }, (_, i) => ({
  id: `p-${i}`,
  name: `Project ${i}`,
}))
const projectBeyondFirstPage: ProjectStub = {
  id: 'p-150',
  name: 'Project 150',
  members: [{ user_id: targetUserId }],
}
// The user's team is the second of two owners, so a lookup that reads one owner misses this one.
const coOwnedProject: ProjectStub = {
  id: 'p-200',
  name: 'Project 200',
  team_ids: ['team-other', 'team-target'],
}
// Two of the user's projects share a name and differ by owning team.
const namesakes: ProjectStub[] = [
  { id: 'p-301', name: 'shared-lib', members: [{ user_id: targetUserId }], teams: [{ id: 't-pay', name: 'Payments' }] },
  { id: 'p-302', name: 'shared-lib', members: [{ user_id: targetUserId }], teams: [{ id: 't-plat', name: 'Platform' }] },
]
const allProjects: ProjectStub[] = [...firstPage, projectBeyondFirstPage, coOwnedProject, ...namesakes]

vi.mock('@/hooks/queries/use-projects', () => ({
  // First page only: omits Project 150.
  useProjects: () => ({
    data: { items: firstPage, total: allProjects.length },
    isLoading: false,
    error: null,
  }),
  // Full, paginated list: includes Project 150.
  useProjectsDropdown: () => ({
    data: { items: allProjects, total: allProjects.length },
    isLoading: false,
    error: null,
  }),
}))

vi.mock('@/hooks/queries/use-teams', () => ({
  useTeams: () => ({
    data: [
      { id: 'team-other', name: 'Other', members: [{ user_id: 'someone-else' }] },
      { id: 'team-target', name: 'Target', members: [{ user_id: targetUserId }] },
    ],
    isLoading: false,
    error: null,
  }),
}))

const noopMutation = () => ({ mutate: vi.fn(), isPending: false })
vi.mock('@/hooks/queries/use-users', () => ({
  useUpdateUser: () => noopMutation(),
  useAdminMigrateUser: () => noopMutation(),
  useAdminResetPassword: () => noopMutation(),
  useAdminDisable2FA: () => noopMutation(),
}))

vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ hasPermission: () => true }),
}))

vi.mock('@/hooks/queries/use-instances', () => ({ useInstanceNames: () => new Map() }))

vi.mock('../UserPermissionsDialog', () => ({
  UserPermissionsDialog: () => null,
}))

function makeUser(): User {
  return {
    id: targetUserId,
    email: 'target@example.com',
    username: 'target',
    is_active: true,
    permissions: [],
    totp_enabled: false,
  }
}

describe('UserDetailsDialog - project membership', () => {
  it("lists a user's project even when it is beyond the first page of 100 projects", () => {
    render(
      <MemoryRouter>
        <UserDetailsDialog user={makeUser()} open onOpenChange={() => {}} />
      </MemoryRouter>,
    )

    expect(screen.getByText('Project 150')).toBeInTheDocument()
    expect(screen.queryByText('No projects found.')).not.toBeInTheDocument()
  })

  it("lists a project any of whose owning teams the user belongs to", () => {
    render(
      <MemoryRouter>
        <UserDetailsDialog user={makeUser()} open onOpenChange={() => {}} />
      </MemoryRouter>,
    )

    expect(screen.getByText('Project 200')).toBeInTheDocument()
  })

  it("names the owner of each of the user's projects whose name another one shares, as the project list does", () => {
    render(
      <MemoryRouter>
        <UserDetailsDialog user={makeUser()} open onOpenChange={() => {}} />
      </MemoryRouter>,
    )

    expect(screen.getAllByText('shared-lib')).toHaveLength(2)
    expect(screen.getByText('Payments')).toBeInTheDocument()
    expect(screen.getByText('Platform')).toBeInTheDocument()
    expect(screen.getByText('Project 150').closest('a')).not.toHaveTextContent('Unassigned')
  })
})

describe('UserDetailsDialog - permissions', () => {
  it('outlines each permission pill like every neutral badge', () => {
    render(
      <MemoryRouter>
        <UserDetailsDialog user={{ ...makeUser(), permissions: ['project:read'] }} open onOpenChange={() => {}} />
      </MemoryRouter>,
    )

    expect(screen.getByText('project:read')).toHaveClass('border-foreground/45')
    expect(screen.getByText('project:read')).not.toHaveClass('border-transparent')
  })
})
