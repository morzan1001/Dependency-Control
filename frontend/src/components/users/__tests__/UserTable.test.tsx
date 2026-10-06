import { fireEvent, render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'

import { UserTable } from '../UserTable'

vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ hasPermission: () => true }) }))
vi.mock('@/hooks/queries/use-users', () => {
  const mutation = () => ({ mutate: vi.fn(), isPending: false })
  return { useDeleteUser: mutation, useInviteUser: mutation, useRevokeInvitation: mutation }
})

describe('UserTable sorting', () => {
  it('offers no sort on Status, which no stored user field backs', () => {
    const onSort = vi.fn()
    render(<UserTable users={[]} page={1} limit={20} onPageChange={vi.fn()} onSelectUser={vi.fn()} onSort={onSort} />)

    fireEvent.click(screen.getByText('Status'))
    fireEvent.click(screen.getByText('Username'))

    expect(onSort.mock.calls).toEqual([['username']])
  })
})
