import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import Login from '../Login'
import Signup from '../Signup'
import ResetPassword from '../ResetPassword'
import AcceptInvite from '../AcceptInvite'

vi.mock('@/hooks/queries/use-auth', () => ({
  useLogin: () => ({ mutate: vi.fn(), isPending: true }),
  useSignup: () => ({ mutate: vi.fn(), isPending: true }),
  useResetPassword: () => ({ mutate: vi.fn(), isPending: true }),
  useAcceptInvitation: () => ({ mutate: vi.fn(), isPending: true }),
  useValidateInvitation: () => ({
    mutate: (
      _token: string,
      opts: { onSuccess: (data: { email: string }) => void },
    ) => opts.onSuccess({ email: 'invitee@example.com' }),
    isPending: false,
  }),
}))

vi.mock('@/hooks/queries/use-system', () => ({
  usePublicConfig: () => ({ data: { oidc_enabled: false, allow_public_registration: true } }),
}))

vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ login: vi.fn(), isAuthenticated: false }),
}))

vi.mock('sonner', () => ({
  toast: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }),
}))

describe('Login page loading state', () => {
  it('disables the submit button and shows the loading label while the login mutation is pending', () => {
    render(
      <MemoryRouter initialEntries={['/login']}>
        <Login />
      </MemoryRouter>,
    )

    const button = screen.getByRole('button', { name: /logging in/i })
    expect(button).toBeDisabled()
  })
})

describe('Signup page loading state', () => {
  it('disables the submit button and shows the loading label while the signup mutation is pending', () => {
    render(
      <MemoryRouter initialEntries={['/signup']}>
        <Signup />
      </MemoryRouter>,
    )

    const button = screen.getByRole('button', { name: /creating account/i })
    expect(button).toBeDisabled()
  })
})

describe('ResetPassword page loading state', () => {
  it('disables the submit button and shows the loading label while the reset mutation is pending', () => {
    render(
      <MemoryRouter initialEntries={['/reset-password?token=abc']}>
        <ResetPassword />
      </MemoryRouter>,
    )

    const button = screen.getByRole('button', { name: /resetting/i })
    expect(button).toBeDisabled()
  })
})

describe('AcceptInvite page loading state', () => {
  it('disables the submit button and shows the loading label while the accept mutation is pending', () => {
    render(
      <MemoryRouter initialEntries={['/accept-invite?token=abc']}>
        <AcceptInvite />
      </MemoryRouter>,
    )

    const button = screen.getByRole('button', { name: /creating account/i })
    expect(button).toBeDisabled()
  })
})
