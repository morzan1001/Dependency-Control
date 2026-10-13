import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { User } from '@/types/user'

import { UserDetailsDialog } from '../UserDetailsDialog'

const { update, auth } = vi.hoisted(() => ({ update: vi.fn(), auth: { granted: [] as string[] } }))

vi.mock('@/api/users', () => ({ userApi: { update } }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ hasPermission: (permission: string) => auth.granted.includes(permission) }),
}))
vi.mock('@/hooks/queries/use-projects', () => ({
  useProjectsDropdown: () => ({ data: { items: [] }, isLoading: false, error: null }),
}))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => ({ data: [], isLoading: false, error: null }) }))

const TARGET: User = {
  id: 'u-target',
  username: 'target',
  email: 'target@corp.com',
  is_active: true,
  auth_provider: 'local',
  permissions: ['project:read'],
  totp_enabled: false,
}

function renderDialog() {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <UserDetailsDialog user={TARGET} open onOpenChange={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('UserDetailsDialog - username', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renames a user whose every permission the caller holds', async () => {
    auth.granted = ['user:update', 'project:read']
    update.mockResolvedValue({ ...TARGET, username: 'target2' })
    renderDialog()

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'target2' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save username' }))

    await waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    expect(update).toHaveBeenCalledWith('u-target', { username: 'target2' })
  })

  it('lets a system manager rename a user who holds a permission the manager lacks', () => {
    auth.granted = ['user:update', 'system:manage']
    renderDialog()

    expect(screen.getByRole('textbox', { name: 'Username' })).toBeEnabled()
  })

  it.each([
    ['without user:update', ['project:read']],
    ['lacking a permission the user holds', ['user:update']],
  ])('shows the username read-only to a caller %s', (_, granted) => {
    auth.granted = granted
    renderDialog()

    expect(screen.queryByRole('textbox', { name: 'Username' })).not.toBeInTheDocument()
    expect(screen.getByText('target')).toBeInTheDocument()
  })
})
