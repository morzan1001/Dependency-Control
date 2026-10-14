import { render, screen, fireEvent, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import UsersPage from '../Users'
import type { User, SystemInvitation } from '@/types/user'
import { SMALL_PAGE_SIZE } from '@/lib/constants'

const mockUseUsers = vi.fn()
const mockUsePendingInvitations = vi.fn()
const noopMutation = () => ({ mutate: vi.fn(), isPending: false })
const mockDeleteUser = vi.fn()
const mockRevokeInvitation = vi.fn()

vi.mock('@/hooks/queries/use-users', () => ({
  useUsers: (...args: unknown[]) => mockUseUsers(...args),
  usePendingInvitations: () => mockUsePendingInvitations(),
  useDeleteUser: () => ({ mutate: mockDeleteUser, isPending: false }),
  useRevokeInvitation: () => ({ mutate: mockRevokeInvitation, isPending: false }),
  useInviteUser: () => noopMutation(),
}))

vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ hasPermission: () => true }),
}))

// Keep the page focused on pagination + invitation rendering; stub dialogs.
vi.mock('@/components/users/InviteUserDialog', () => ({
  InviteUserDialog: () => <div data-testid="invite-dialog" />,
}))
vi.mock('@/components/users/UserDetailsDialog', () => ({
  UserDetailsDialog: ({ open }: { open: boolean }) => (open ? <div>User Details</div> : null),
}))

function makeUser(i: number): User {
  return {
    id: `user-${i}`,
    email: `user${i}@example.com`,
    username: `user${i}`,
    is_active: true,
    permissions: [],
    totp_enabled: false,
  }
}

function makeInvitation(i: number): SystemInvitation {
  return {
    id: `invite-${i}`,
    email: `invite${i}@example.com`,
    token: `tok-${i}`,
    invited_by: 'admin',
    created_at: '2026-07-01T00:00:00Z',
    expires_at: '2026-08-01T00:00:00Z',
    is_used: false,
  }
}

beforeEach(() => {
  mockUseUsers.mockReset()
  mockUsePendingInvitations.mockReset()
  mockDeleteUser.mockReset()
  mockRevokeInvitation.mockReset()
})

describe('UsersPage - invitations & pagination', () => {
  it('does not render a phantom Next button when the real user page is not full', () => {
    // (limit - 2) real users (< limit) + 3 pending invitations on page 1.
    const users = Array.from({ length: SMALL_PAGE_SIZE - 2 }, (_, i) => makeUser(i))
    mockUseUsers.mockReturnValue({ data: users, isLoading: false, error: null })
    mockUsePendingInvitations.mockReturnValue({
      data: [makeInvitation(0), makeInvitation(1), makeInvitation(2)],
      isLoading: false,
    })

    render(<UsersPage />)

    expect(screen.getAllByText('Invited')).toHaveLength(3)
    expect(screen.getByText('user0')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Next/i })).not.toBeInTheDocument()
  })

  it('does not duplicate pending invitations onto subsequent pages', () => {
    const limit = SMALL_PAGE_SIZE
    const fullPage = Array.from({ length: limit }, (_, i) => makeUser(i))
    const secondPage = Array.from({ length: 5 }, (_, i) => makeUser(limit + i))
    const invitations = [makeInvitation(0), makeInvitation(1), makeInvitation(2)]

    mockUseUsers.mockImplementation((skip: number) => ({
      data: skip === 0 ? fullPage : secondPage,
      isLoading: false,
      error: null,
    }))
    mockUsePendingInvitations.mockReturnValue({ data: invitations, isLoading: false })

    render(<UsersPage />)

    expect(screen.getAllByText('Invited')).toHaveLength(3)
    const nextButton = screen.getByRole('button', { name: /Next/i })

    fireEvent.click(nextButton)

    expect(screen.queryAllByText('Invited')).toHaveLength(0)
    expect(screen.getByText(`user${limit}`)).toBeInTheDocument()
  })
})

describe('UsersPage - opening a row', () => {
  it('opens the details of a user but not of a pending invitation', () => {
    mockUseUsers.mockReturnValue({ data: [makeUser(0)], isLoading: false, error: null })
    mockUsePendingInvitations.mockReturnValue({ data: [makeInvitation(0)], isLoading: false })

    render(<UsersPage />)

    fireEvent.click(screen.getAllByText('invite0@example.com')[0])
    expect(screen.queryByText('User Details')).not.toBeInTheDocument()

    fireEvent.click(screen.getByText('user0'))
    expect(screen.getByText('User Details')).toBeInTheDocument()
  })
})

describe('UsersPage - removing a row', () => {
  it('revokes a pending invitation instead of deleting a user', () => {
    mockUseUsers.mockReturnValue({ data: [makeUser(0)], isLoading: false, error: null })
    mockUsePendingInvitations.mockReturnValue({ data: [makeInvitation(0)], isLoading: false })

    render(<UsersPage />)

    const row = screen.getAllByText('invite0@example.com')[0].closest('tr') as HTMLElement
    const buttons = within(row).getAllByRole('button')
    fireEvent.click(buttons[buttons.length - 1])
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }))

    expect(mockRevokeInvitation).toHaveBeenCalledWith('invite-0', expect.anything())
    expect(mockDeleteUser).not.toHaveBeenCalled()
  })

  it("names each row's remove button by what it removes, like the other icon buttons", () => {
    mockUseUsers.mockReturnValue({ data: [makeUser(0)], isLoading: false, error: null })
    mockUsePendingInvitations.mockReturnValue({ data: [makeInvitation(0)], isLoading: false })

    render(<UsersPage />)

    const userRow = screen.getByText('user0').closest('tr') as HTMLElement
    const invitationRow = screen.getAllByText('invite0@example.com')[0].closest('tr') as HTMLElement
    expect(within(userRow).getByRole('button', { name: 'Delete user' })).toBeInTheDocument()
    expect(within(invitationRow).getByRole('button', { name: 'Revoke invitation' })).toBeInTheDocument()
  })

  it('names the user to delete in bold, wrapped like the username in the user dialogs', () => {
    mockUseUsers.mockReturnValue({ data: [makeUser(0)], isLoading: false, error: null })
    mockUsePendingInvitations.mockReturnValue({ data: [], isLoading: false })

    render(<UsersPage />)

    const row = screen.getByText('user0').closest('tr') as HTMLElement
    const buttons = within(row).getAllByRole('button')
    fireEvent.click(buttons[buttons.length - 1])

    expect(within(screen.getByRole('dialog')).getByText('user0', { selector: 'strong' })).toHaveClass('wrap-anywhere')
  })

  it('names the invitation to revoke in bold, like the user to delete', () => {
    mockUseUsers.mockReturnValue({ data: [], isLoading: false, error: null })
    mockUsePendingInvitations.mockReturnValue({ data: [makeInvitation(0)], isLoading: false })

    render(<UsersPage />)

    const row = screen.getAllByText('invite0@example.com')[0].closest('tr') as HTMLElement
    const buttons = within(row).getAllByRole('button')
    fireEvent.click(buttons[buttons.length - 1])

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('invite0@example.com', { selector: 'strong' })).toHaveClass('wrap-anywhere')
    expect(within(dialog).getByText(/Revoke the invitation for/)).toHaveTextContent('Revoke the invitation for invite0@example.com?')
  })

  it('deletes a user through a Delete button', () => {
    mockUseUsers.mockReturnValue({ data: [makeUser(0)], isLoading: false, error: null })
    mockUsePendingInvitations.mockReturnValue({ data: [], isLoading: false })

    render(<UsersPage />)

    const row = screen.getByText('user0').closest('tr') as HTMLElement
    const buttons = within(row).getAllByRole('button')
    fireEvent.click(buttons[buttons.length - 1])
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))

    expect(mockDeleteUser).toHaveBeenCalledWith('user-0', expect.anything())
    expect(mockRevokeInvitation).not.toHaveBeenCalled()
  })
})

describe('UsersPage - sorting', () => {
  it('sorts the users by a clicked column, descending first, from the first page', () => {
    const limit = SMALL_PAGE_SIZE
    mockUseUsers.mockReturnValue({ data: Array.from({ length: limit }, (_, i) => makeUser(i)), isLoading: false, error: null })
    mockUsePendingInvitations.mockReturnValue({ data: [], isLoading: false })
    const lastQuery = () => mockUseUsers.mock.calls[mockUseUsers.mock.calls.length - 1]
    render(<UsersPage />)
    expect(lastQuery()).toEqual([0, limit, '', 'username', 'asc'])
    fireEvent.click(screen.getByRole('button', { name: /Next/i }))

    fireEvent.click(screen.getByRole('columnheader', { name: 'Email' }))

    expect(lastQuery()).toEqual([0, limit, '', 'email', 'desc'])
  })

  it('offers no sort on the pending invitations, which are not paged from the server', () => {
    mockUseUsers.mockReturnValue({ data: [], isLoading: false, error: null })
    mockUsePendingInvitations.mockReturnValue({ data: [makeInvitation(0)], isLoading: false })

    render(<UsersPage />)

    const [invitationsEmail] = screen.getAllByRole('columnheader', { name: 'Email' })
    expect(invitationsEmail).not.toHaveClass('cursor-pointer')
  })
})
