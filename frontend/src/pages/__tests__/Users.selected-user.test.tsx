import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { PRESET_VIEWER } from '@/lib/permissions'
import type { User } from '@/types/user'

import UsersPage from '../Users'

const { mockUseUsers, updateUser, idle } = vi.hoisted(() => ({
  mockUseUsers: vi.fn(),
  updateUser: vi.fn(),
  idle: () => ({ mutate: () => undefined, isPending: false }),
}))

vi.mock('@/hooks/queries/use-users', () => ({
  useUsers: (...args: unknown[]) => mockUseUsers(...args),
  usePendingInvitations: () => ({ data: [], isLoading: false }),
  useDeleteUser: idle,
  useRevokeInvitation: idle,
  useInviteUser: idle,
  useUpdateUser: () => ({ mutate: updateUser, isPending: false }),
  useAdminMigrateUser: idle,
  useAdminResetPassword: idle,
  useAdminDisable2FA: idle,
}))
vi.mock('@/hooks/queries/use-projects', () => ({
  useProjectsDropdown: () => ({ data: { items: [] }, isLoading: false, error: null }),
}))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => ({ data: [], isLoading: false, error: null }) }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ hasPermission: () => true }) }))
vi.mock('@/components/users/InviteUserDialog', () => ({ InviteUserDialog: () => null }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

function lena(permissions: string[]): User {
  return { id: 'u-lena', email: 'lena@corp.com', username: 'lena', is_active: true, permissions, totp_enabled: false }
}

// What GET /users answers on each (re)fetch.
function serverHolds(user: User) {
  mockUseUsers.mockReturnValue({ data: [user], isLoading: false, error: null })
}

const page = () => (
  <MemoryRouter>
    <UsersPage />
  </MemoryRouter>
)

beforeEach(() => {
  vi.clearAllMocks()
  updateUser.mockImplementation((_vars, options: { onSuccess: () => void }) => options.onSuccess())
})

describe('UsersPage user details', () => {
  it('shows what the refetched user list holds while the dialog is open', () => {
    serverHolds(lena(['project:read']))
    const { rerender } = render(page())
    fireEvent.click(screen.getByText('lena'))

    serverHolds(lena(['project:read', 'team:read']))
    rerender(page())

    expect(within(screen.getByRole('dialog')).getByText('team:read')).toBeInTheDocument()
  })

  it('starts a second permission edit from what the first one saved', () => {
    serverHolds(lena(['project:read']))
    const { rerender } = render(page())
    fireEvent.click(screen.getByText('lena'))
    fireEvent.click(screen.getByRole('button', { name: 'Manage Permissions' }))
    fireEvent.click(screen.getByRole('button', { name: /Viewer/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    serverHolds(lena([...PRESET_VIEWER]))
    rerender(page())
    fireEvent.click(screen.getByRole('button', { name: 'Manage Permissions' }))

    expect(screen.getByText(`Selected: ${PRESET_VIEWER.length} permissions`)).toBeInTheDocument()
  })

  it('drops unsaved permission edits when the dialog is cancelled', () => {
    serverHolds(lena(['project:read']))
    render(page())
    fireEvent.click(screen.getByText('lena'))
    fireEvent.click(screen.getByRole('button', { name: 'Manage Permissions' }))
    fireEvent.click(screen.getByRole('button', { name: /Clear All/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    fireEvent.click(screen.getByRole('button', { name: 'Manage Permissions' }))

    expect(screen.getByText('Selected: 1 permission')).toBeInTheDocument()
  })
})
