import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import Login from '../Login'

vi.mock('@/hooks/queries/use-auth', () => ({ useLogin: () => ({ mutate: vi.fn(), isPending: false }) }))
vi.mock('@/hooks/queries/use-system', () => ({ usePublicConfig: () => ({ data: { password_reset_enabled: true } }) }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ login: vi.fn() }) }))

describe('Login', () => {
  it('lets a password manager fill in the stored password', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>,
    )

    expect(screen.getByLabelText('Password')).toHaveAttribute('autocomplete', 'current-password')
  })
})
