import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { toast } from 'sonner'
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
const MANAGER = ['user:update', 'project:read']

function renderDialog() {
  const onUserUpdated = vi.fn()
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <UserDetailsDialog user={TARGET} open onOpenChange={() => {}} onUserUpdated={onUserUpdated} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return onUserUpdated
}

function openRename() {
  fireEvent.click(screen.getByRole('button', { name: 'Rename' }))
  const dialog = screen.getByRole('dialog', { name: 'Rename target' })
  return {
    dialog,
    field: within(dialog).getByLabelText('Username'),
    save: within(dialog).getByRole('button', { name: 'Save Changes' }),
  }
}

describe('UserDetailsDialog - username', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renames a user whose every permission the caller holds', async () => {
    auth.granted = MANAGER
    update.mockResolvedValue({ ...TARGET, username: 'target2' })
    const onUserUpdated = renderDialog()
    const { field, save } = openRename()

    expect(field).toHaveValue('target')
    fireEvent.change(field, { target: { value: ' target2 ' } })
    fireEvent.click(save)

    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Rename target' })).not.toBeInTheDocument())
    expect(update.mock.calls).toEqual([['u-target', { username: 'target2' }]])
    expect(onUserUpdated).toHaveBeenCalledWith({ ...TARGET, username: 'target2' })
    expect(toast.success).toHaveBeenCalledTimes(1)
  })

  it('offers no save while the name is unchanged', () => {
    auth.granted = MANAGER
    renderDialog()
    const { field, save } = openRename()

    expect(save).toBeDisabled()
    fireEvent.change(field, { target: { value: ' target ' } })
    expect(save).toBeDisabled()
    fireEvent.change(field, { target: { value: 'target2' } })
    expect(save).toBeEnabled()
  })

  it.each(['', '   '])('offers no save for the blank name %j', (blank) => {
    auth.granted = MANAGER
    renderDialog()
    const { field, save } = openRename()

    fireEvent.change(field, { target: { value: blank } })
    expect(save).toBeDisabled()
    fireEvent.click(save)

    expect(update).not.toHaveBeenCalled()
  })

  it('drops the typed name when the rename is cancelled', () => {
    auth.granted = MANAGER
    renderDialog()
    const { dialog, field } = openRename()
    fireEvent.change(field, { target: { value: 'target2' } })

    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))

    expect(screen.queryByRole('dialog', { name: 'Rename target' })).not.toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
    expect(openRename().field).toHaveValue('target')
  })

  it('keeps the rename open and says why the name was refused', async () => {
    auth.granted = MANAGER
    update.mockRejectedValue({ response: { data: { detail: 'Username already taken' } } })
    const onUserUpdated = renderDialog()
    const { dialog, field, save } = openRename()

    fireEvent.change(field, { target: { value: 'otto' } })
    fireEvent.click(save)

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Error', { description: 'Username already taken' }))
    expect(dialog).toBeInTheDocument()
    expect(field).toHaveValue('otto')
    expect(onUserUpdated).not.toHaveBeenCalled()
  })

  it('lets a system manager rename a user who holds a permission the manager lacks', () => {
    auth.granted = ['user:update', 'system:manage']
    renderDialog()

    expect(screen.getByRole('button', { name: 'Rename' })).toBeInTheDocument()
  })

  it.each([
    ['without user:update', ['project:read']],
    ['lacking a permission the user holds', ['user:update']],
  ])('offers no rename to a caller %s', (_, granted) => {
    auth.granted = granted
    renderDialog()

    expect(screen.queryByRole('button', { name: 'Rename' })).not.toBeInTheDocument()
    expect(screen.getByText('target')).toBeInTheDocument()
  })
})
