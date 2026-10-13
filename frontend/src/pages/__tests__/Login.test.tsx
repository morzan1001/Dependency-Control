import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import Login from '../Login'

const { loginMutate, config } = vi.hoisted(() => ({
  loginMutate: vi.fn(),
  config: { current: {} as Record<string, boolean> },
}))

vi.mock('@/hooks/queries/use-auth', () => ({ useLogin: () => ({ mutate: loginMutate, isPending: false }) }))
vi.mock('@/hooks/queries/use-system', () => ({ usePublicConfig: () => ({ data: config.current }) }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ login: vi.fn() }) }))

function renderLogin() {
  render(
    <MemoryRouter>
      <Login />
    </MemoryRouter>,
  )
}

function reachTwoFactorStep() {
  loginMutate.mockImplementation((_credentials, opts: { onError: (error: unknown) => void }) =>
    opts.onError({ response: { status: 401, data: { detail: '2FA required' } } }),
  )
  renderLogin()
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'lena' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Correct-Horse-1' } })
  fireEvent.click(screen.getByRole('button', { name: 'Login' }))
}

describe('Login', () => {
  beforeEach(() => {
    loginMutate.mockReset()
    config.current = { password_reset_enabled: true }
  })

  it('lets a password manager fill in the stored username and password', () => {
    renderLogin()

    expect(screen.getByLabelText('Username')).toHaveAttribute('autocomplete', 'username')
    expect(screen.getByLabelText('Password')).toHaveAttribute('autocomplete', 'current-password')
  })

  it('offers sign-up as a text line under a full-width Login, like the other auth cards', () => {
    config.current = { password_reset_enabled: true, allow_public_registration: true }
    renderLogin()

    expect(screen.getByRole('button', { name: 'Login' })).toHaveClass('w-full')
    expect(screen.getByText(/Don't have an account\?/)).toContainElement(screen.getByRole('link', { name: 'Sign Up' }))
  })

  it('lets the device offer the 2FA code from an authenticator, like the profile setup dialog', () => {
    reachTwoFactorStep()

    expect(screen.getByLabelText('2FA Code')).toHaveAttribute('autocomplete', 'one-time-code')
    expect(screen.getByLabelText('2FA Code')).toHaveAttribute('inputmode', 'numeric')
    expect(screen.getByLabelText('2FA Code')).toHaveAttribute('maxlength', '6')
  })

  it('leaves the 2FA step through a Cancel link under a full-width Verify', () => {
    reachTwoFactorStep()

    expect(screen.getByRole('button', { name: 'Verify' })).toHaveClass('w-full')
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(screen.queryByLabelText('2FA Code')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Login' })).toBeInTheDocument()
  })
})
