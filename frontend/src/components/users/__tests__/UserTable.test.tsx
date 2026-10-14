import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'

import type { User } from '@/types/user'

import { UserTable } from '../UserTable'

vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ hasPermission: () => true }) }))
const mockUseInviteUser = vi.fn()
const mockUseRevokeInvitation = vi.fn()
vi.mock('@/hooks/queries/use-users', () => {
  const mutation = () => ({ mutate: vi.fn(), isPending: false })
  return {
    useDeleteUser: mutation,
    useInviteUser: (meta: unknown) => {
      mockUseInviteUser(meta)
      return mutation()
    },
    useRevokeInvitation: (meta: unknown) => {
      mockUseRevokeInvitation(meta)
      return mutation()
    },
  }
})

describe('UserTable sorting', () => {
  it('offers no sort on Status, which no stored user field backs', () => {
    const toggleSort = vi.fn()
    const sort = { sortBy: 'username', sortOrder: 'asc' as const, toggleSort }
    render(<UserTable users={[]} page={1} limit={20} onPageChange={vi.fn()} onSelectUser={vi.fn()} sort={sort} />)

    fireEvent.click(screen.getByText('Status'))
    fireEvent.click(screen.getByText('Username'))

    expect(toggleSort.mock.calls.map(([column]) => column)).toEqual(['username'])
  })
})

describe('UserTable status', () => {
  it('labels a pending invitation, an active account and a deactivated one', () => {
    const row = (id: string, is_active: boolean, status: User['status']): User =>
      ({ id, username: id, email: `${id}@corp.com`, is_active, status, permissions: [], totp_enabled: false })
    render(
      <UserTable
        users={[row('invitee', false, 'invited'), row('lena', true, 'active'), row('otto', false, 'active')]}
        page={0}
        limit={20}
        onPageChange={vi.fn()}
      />,
    )

    const statuses = screen.getAllByRole('row').slice(1).map((tr) => within(tr).getAllByRole('cell')[2].textContent)
    expect(statuses).toEqual(['Invited', 'Active', 'Inactive'])
  })
})

describe('UserTable invitation failures', () => {
  it('names a failed revocation and a failed resend, which the error toast completes with the reason', () => {
    render(<UserTable users={[]} page={0} limit={20} onPageChange={vi.fn()} />)

    expect(mockUseRevokeInvitation).toHaveBeenCalledWith({ errorTitle: 'Failed to revoke invitation' })
    expect(mockUseInviteUser).toHaveBeenCalledWith({ errorTitle: 'Failed to resend invitation' })
  })
})
