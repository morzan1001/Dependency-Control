import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import UsersPage from '../Users'
import type { User, SystemInvitation } from '@/types/user'
import { SMALL_PAGE_SIZE } from '@/lib/constants'

// --- Mocks -----------------------------------------------------------------

const mockUseUsers = vi.fn()
const mockUsePendingInvitations = vi.fn()
const noopMutation = () => ({ mutate: vi.fn(), isPending: false })

vi.mock('@/hooks/queries/use-users', () => ({
  useUsers: (...args: unknown[]) => mockUseUsers(...args),
  usePendingInvitations: () => mockUsePendingInvitations(),
  useDeleteUser: () => noopMutation(),
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
  UserDetailsDialog: () => null,
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
})

describe('UsersPage - invitations & pagination', () => {
  it('does not render a phantom Next button when the real user page is not full', () => {
    // (limit - 2) real users (< limit) + 3 pending invitations on page 1.
    // Merging invitations into the paginated array previously pushed the
    // length to >= limit, producing a phantom Next button.
    const users = Array.from({ length: SMALL_PAGE_SIZE - 2 }, (_, i) => makeUser(i))
    mockUseUsers.mockReturnValue({ data: users, isLoading: false, error: null })
    mockUsePendingInvitations.mockReturnValue({
      data: [makeInvitation(0), makeInvitation(1), makeInvitation(2)],
      isLoading: false,
    })

    render(<UsersPage />)

    // Invitations are visible on page 1.
    expect(screen.getAllByText('Invited')).toHaveLength(3)
    // Real users are visible.
    expect(screen.getByText('user0')).toBeInTheDocument()
    // No phantom "Next": there is no further page of real users.
    expect(screen.queryByRole('button', { name: /Next/i })).not.toBeInTheDocument()
  })

  it('does not duplicate pending invitations onto subsequent pages', () => {
    const limit = SMALL_PAGE_SIZE
    const fullPage = Array.from({ length: limit }, (_, i) => makeUser(i))
    const secondPage = Array.from({ length: 5 }, (_, i) => makeUser(limit + i))
    const invitations = [makeInvitation(0), makeInvitation(1), makeInvitation(2)]

    // Return page-specific data based on the `skip` argument.
    mockUseUsers.mockImplementation((skip: number) => ({
      data: skip === 0 ? fullPage : secondPage,
      isLoading: false,
      error: null,
    }))
    mockUsePendingInvitations.mockReturnValue({ data: invitations, isLoading: false })

    render(<UsersPage />)

    // Page 1: full page -> Next is offered; invitations shown once.
    expect(screen.getAllByText('Invited')).toHaveLength(3)
    const nextButton = screen.getByRole('button', { name: /Next/i })

    fireEvent.click(nextButton)

    // Page 2: invitations must NOT be repeated.
    expect(screen.queryAllByText('Invited')).toHaveLength(0)
    // Page-2 real users render.
    expect(screen.getByText(`user${limit}`)).toBeInTheDocument()
  })
})
