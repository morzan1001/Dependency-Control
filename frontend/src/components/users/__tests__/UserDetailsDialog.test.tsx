import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'

import { UserDetailsDialog } from '../UserDetailsDialog'
import type { User } from '@/types/user'

interface ProjectStub {
  id: string
  name: string
  owner_id?: string
  members?: { user_id: string }[]
  team_id?: string
}

// useProjects returns only the first 100-project page (no Project 150); useProjectsDropdown paginates the full list, so the dialog must use the latter.
const targetUserId = 'user-target'
const firstPage: ProjectStub[] = Array.from({ length: 100 }, (_, i) => ({
  id: `p-${i}`,
  name: `Project ${i}`,
  owner_id: 'someone-else',
}))
const projectBeyondFirstPage: ProjectStub = {
  id: 'p-150',
  name: 'Project 150',
  owner_id: targetUserId,
}
const allProjects: ProjectStub[] = [...firstPage, projectBeyondFirstPage]

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
  useTeams: () => ({ data: [], isLoading: false, error: null }),
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
})
