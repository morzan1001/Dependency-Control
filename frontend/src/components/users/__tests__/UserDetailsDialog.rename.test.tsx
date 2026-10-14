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
const OUTSIDE_RULE =
  'A username has 2 to 64 letters, digits, dots, underscores, hyphens or single spaces and starts with a letter or digit'
const NOT_MANAGEABLE = "Cannot manage a user who holds permissions you don't hold"

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
    expect(toast.success).toHaveBeenCalledWith('Username updated')
  })

  it('saves and confirms the name as it stands, like the other edits', async () => {
    auth.granted = MANAGER
    update.mockResolvedValue(TARGET)
    const onUserUpdated = renderDialog()
    const { save } = openRename()

    expect(save).toBeEnabled()
    fireEvent.click(save)

    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Rename target' })).not.toBeInTheDocument())
    expect(update.mock.calls).toEqual([['u-target', { username: 'target' }]])
    expect(onUserUpdated).toHaveBeenCalledWith(TARGET)
    expect(toast.success).toHaveBeenCalledWith('Username updated')
  })

  it.each(['', '   '])('says under the field that the blank name %j needs a username and sends nothing, like the profile card', async (blank) => {
    auth.granted = MANAGER
    renderDialog()
    const { dialog, field, save } = openRename()

    fireEvent.change(field, { target: { value: blank } })
    expect(save).toBeEnabled()
    fireEvent.click(save)

    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Enter a username.')
    expect(field).toHaveAccessibleDescription('Enter a username.')
    expect(update).not.toHaveBeenCalled()
    fireEvent.change(field, { target: { value: 'target2' } })
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument()
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

  it.each([
    { status: 400, reason: 'Username already taken' },
    { status: 422, reason: OUTSIDE_RULE },
  ])('keeps the rename open and says under the field why the name was refused with $status', async ({ status, reason }) => {
    auth.granted = MANAGER
    update.mockRejectedValue({ response: { status, data: { detail: reason } } })
    const onUserUpdated = renderDialog()
    const { dialog, field, save } = openRename()

    fireEvent.change(field, { target: { value: 'otto' } })
    fireEvent.click(save)

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(reason)
    expect(field).toHaveAccessibleDescription(reason)
    expect(field).toHaveValue('otto')
    expect(onUserUpdated).not.toHaveBeenCalled()
    expect(toast.error).not.toHaveBeenCalled()
    fireEvent.change(field, { target: { value: 'otto2' } })
    await waitFor(() => expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument())
  })

  it.each([
    { error: { response: { status: 403, data: { detail: NOT_MANAGEABLE } } }, message: NOT_MANAGEABLE },
    { error: new Error('Network Error'), message: 'Network Error' },
  ])('toasts a rename that failed for another reason: $message', async ({ error, message }) => {
    auth.granted = MANAGER
    update.mockRejectedValue(error)
    renderDialog()
    const { dialog, field, save } = openRename()

    fireEvent.change(field, { target: { value: 'otto' } })
    fireEvent.click(save)

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to update username', { description: message }))
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument()
    expect(field).toHaveValue('otto')
  })

  it('wraps the username by the one rule of the user dialog titles wherever these dialogs show it', () => {
    auth.granted = MANAGER
    renderDialog()

    expect(screen.getByRole('heading', { name: 'User Details: target' })).toHaveClass('wrap-anywhere')
    expect(screen.getByText('target', { selector: 'span' })).toHaveClass('wrap-anywhere')
    expect(screen.getByText('target@corp.com')).toHaveClass('wrap-anywhere')
    expect(within(openRename().dialog).getByRole('heading', { name: 'Rename target' })).toHaveClass('wrap-anywhere')
  })

  it('offers a rename wherever it offers Deactivate, also for a user who holds a permission the caller lacks', () => {
    auth.granted = ['user:update']
    renderDialog()

    expect(screen.getByRole('button', { name: 'Rename' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Deactivate' })).toBeInTheDocument()
  })

  it('offers no rename to a caller without user:update', () => {
    auth.granted = ['project:read']
    renderDialog()

    expect(screen.queryByRole('button', { name: 'Rename' })).not.toBeInTheDocument()
    expect(screen.getByText('target')).toBeInTheDocument()
  })
})
