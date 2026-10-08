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
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))

    expect(mockRevokeInvitation).toHaveBeenCalledWith('invite-0', expect.anything())
    expect(mockDeleteUser).not.toHaveBeenCalled()
  })
})
