import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { userApi } from '@/api/users'
import { PRESET_VIEWER } from '@/lib/permissions'
import type { User } from '@/types/user'

import UsersPage from '../Users'

vi.mock('@/api/users', () => ({
  userApi: {
    getAll: vi.fn(),
    getPendingInvitations: () => Promise.resolve([]),
    update: vi.fn(),
    adminMigrateToLocal: vi.fn(),
    adminDisable2FA: vi.fn(),
  },
}))
vi.mock('@/api/teams', () => ({ teamApi: { getAll: () => Promise.resolve([]) } }))
vi.mock('@/hooks/queries/use-projects', () => ({
  useProjectsDropdown: () => ({ data: { items: [] }, isLoading: false, error: null }),
}))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ hasPermission: () => true }) }))
vi.mock('@/components/users/InviteUserDialog', () => ({ InviteUserDialog: () => null }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

function lena(permissions: string[]): User {
  return { id: 'u-lena', email: 'lena@corp.com', username: 'lena', is_active: true, permissions, totp_enabled: false }
}

async function openLena() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <UsersPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  fireEvent.click(await screen.findByText('lena'))
  return client
}

async function renameLenaOffThePage(user: User) {
  vi.mocked(userApi.getAll).mockResolvedValueOnce([user]).mockResolvedValue([])
  vi.mocked(userApi.update).mockResolvedValueOnce({ ...user, username: 'zoe' })
  await openLena()
  fireEvent.click(screen.getByRole('button', { name: 'Rename' }))
  const rename = screen.getByRole('dialog', { name: 'Rename lena' })
  fireEvent.change(within(rename).getByLabelText('Username'), { target: { value: 'zoe' } })
  fireEvent.click(within(rename).getByRole('button', { name: 'Save Changes' }))
  return screen.findByRole('dialog', { name: 'User Details: zoe' })
}

beforeEach(() => vi.resetAllMocks())

describe('UsersPage user details', () => {
  it('shows what the refetched user list holds while the dialog is open', async () => {
    vi.mocked(userApi.getAll)
      .mockResolvedValueOnce([lena(['project:read'])])
      .mockResolvedValueOnce([lena(['project:read', 'team:read'])])
    const client = await openLena()

    await client.invalidateQueries()

    expect(await within(screen.getByRole('dialog')).findByText('team:read')).toBeInTheDocument()
  })

  it('starts a second permission edit from what the first one saved', async () => {
    let answerRefetch: (users: User[]) => void = () => undefined
    vi.mocked(userApi.getAll)
      .mockResolvedValueOnce([lena(['project:read'])])
      .mockReturnValueOnce(new Promise((resolve) => (answerRefetch = resolve)))
    vi.mocked(userApi.update).mockResolvedValue(lena([...PRESET_VIEWER]))
    await openLena()
    fireEvent.click(screen.getByRole('button', { name: 'Manage Permissions' }))
    fireEvent.click(screen.getByRole('button', { name: /Viewer/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    // The save runs on microtasks only, so an editor that closes on the PUT alone is gone after one task.
    await act(() => new Promise((resolve) => setTimeout(resolve, 0)))

    expect(userApi.getAll).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('button', { name: 'Saving...' })).toBeDisabled()

    answerRefetch([lena([...PRESET_VIEWER])])
    const details = await screen.findByRole('dialog', { name: 'User Details: lena' })
    await within(details).findByText('team:read')
    fireEvent.click(within(details).getByRole('button', { name: 'Manage Permissions' }))

    expect(screen.getByText(`Selected: ${PRESET_VIEWER.length} permissions`)).toBeInTheDocument()
  })

  it('keeps a renamed user open under the new name once the rename moves them off the page', async () => {
    expect(await renameLenaOffThePage(lena(['project:read']))).toBeInTheDocument()
  })

  it('starts a permission edit from the last one saved for a user a rename moved off the page', async () => {
    const details = await renameLenaOffThePage(lena(['project:read']))
    vi.mocked(userApi.update).mockResolvedValueOnce({ ...lena([...PRESET_VIEWER]), username: 'zoe' })
    fireEvent.click(within(details).getByRole('button', { name: 'Manage Permissions' }))
    fireEvent.click(screen.getByRole('button', { name: /Viewer/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Manage Permissions for zoe' })).not.toBeInTheDocument(),
    )

    fireEvent.click(within(details).getByRole('button', { name: 'Manage Permissions' }))

    expect(screen.getByText(`Selected: ${PRESET_VIEWER.length} permissions`)).toBeInTheDocument()
  })

  it('offers the password reset once a user a rename moved off the page is migrated', async () => {
    const sso: User = { ...lena(['project:read']), auth_provider: 'gitlab' }
    const details = await renameLenaOffThePage(sso)
    vi.mocked(userApi.adminMigrateToLocal).mockResolvedValue({ ...sso, username: 'zoe', auth_provider: 'local' })

    fireEvent.click(within(details).getByRole('button', { name: 'Migrate to Local' }))

    expect(await within(details).findByRole('button', { name: 'Send Reset Email' })).toBeInTheDocument()
  })

  it('drops the 2FA action once it is disabled for a user a rename moved off the page', async () => {
    const enrolled: User = { ...lena(['project:read']), totp_enabled: true }
    const details = await renameLenaOffThePage(enrolled)
    vi.mocked(userApi.adminDisable2FA).mockResolvedValue({ ...enrolled, username: 'zoe', totp_enabled: false })

    fireEvent.click(within(details).getByRole('button', { name: 'Disable 2FA' }))

    await waitFor(() =>
      expect(within(details).queryByRole('button', { name: 'Disable 2FA' })).not.toBeInTheDocument(),
    )
  })

  it('leaves a closed dialog closed when the list is refetched', async () => {
    vi.mocked(userApi.getAll).mockResolvedValue([lena(['project:read'])])
    const client = await openLena()

    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }))
    await client.invalidateQueries()

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('drops unsaved permission edits when the dialog is cancelled', async () => {
    vi.mocked(userApi.getAll).mockResolvedValue([lena(['project:read'])])
    await openLena()
    fireEvent.click(screen.getByRole('button', { name: 'Manage Permissions' }))
    fireEvent.click(screen.getByRole('button', { name: /Clear All/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    fireEvent.click(screen.getByRole('button', { name: 'Manage Permissions' }))

    expect(screen.getByText('Selected: 1 permission')).toBeInTheDocument()
  })
})
