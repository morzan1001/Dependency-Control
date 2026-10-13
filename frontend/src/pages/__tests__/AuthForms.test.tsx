import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import AcceptInvite from '../AcceptInvite'
import Login from '../Login'
import RequestEmailLink from '../RequestEmailLink'
import ResetPassword from '../ResetPassword'
import Signup from '../Signup'
import VerifyEmail from '../VerifyEmail'

const { loginRefusal } = vi.hoisted(() => ({ loginRefusal: { current: undefined as unknown } }))

vi.mock('@/hooks/queries/use-auth', () => ({
  useLogin: () => ({
    mutate: (_credentials: unknown, opts: { onError: (error: unknown) => void }) => opts.onError(loginRefusal.current),
    isPending: false,
  }),
  useSignup: () => ({ mutate: vi.fn(), isPending: false }),
  useAcceptInvitation: () => ({ mutate: vi.fn(), isPending: false }),
  useResetPassword: () => ({ mutate: vi.fn(), isPending: false }),
  useValidateInvitation: () => ({
    mutate: (_token: string, opts: { onSuccess: (data: { email: string }) => void }) =>
      opts.onSuccess({ email: 'invitee@example.com' }),
    isPending: false,
  }),
}))
vi.mock('@/hooks/queries/use-system', () => ({ usePublicConfig: () => ({ data: { password_reset_enabled: true } }) }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ login: vi.fn() }) }))

const unauthorized = (detail: string) => ({ response: { status: 401, data: { detail } } })

function logIn() {
  render(
    <MemoryRouter>
      <Login />
    </MemoryRouter>,
  )
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'lena' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'wrong' } })
  fireEvent.click(screen.getByRole('button', { name: 'Login' }))
}

function mistypeConfirmation(page: React.ReactElement, path: string) {
  render(<MemoryRouter initialEntries={[path]}>{page}</MemoryRouter>)
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'lena' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Battery-Staple-2' } })
  fireEvent.change(screen.getByLabelText('Confirm Password'), { target: { value: 'Battery-Staple-3' } })
  fireEvent.submit(screen.getByLabelText('Password').closest('form') as HTMLFormElement)
}

describe('auth page announcements', () => {
  beforeEach(() => {
    loginRefusal.current = undefined
  })

  it('announces a refused login', () => {
    loginRefusal.current = unauthorized('Incorrect username or password')

    logIn()

    expect(screen.getByRole('alert')).toHaveTextContent('Incorrect username or password')
  })

  it('announces an unverified address together with its resend link', () => {
    loginRefusal.current = unauthorized('Email not verified')

    logIn()

    expect(screen.getByRole('alert')).toHaveTextContent('Email not verified.')
    expect(screen.getByRole('link', { name: 'Resend verification email' })).toHaveAttribute('href', '/resend-verification')
  })

  it('reads out the message another page sent to the login', () => {
    const message = 'Account created successfully. Please login.'
    render(
      <MemoryRouter initialEntries={[{ pathname: '/login', state: { message } }]}>
        <Login />
      </MemoryRouter>,
    )

    expect(screen.getByRole('status')).toHaveTextContent(message)
  })

  it.each([
    { name: 'Signup', page: <Signup />, path: '/signup' },
    { name: 'AcceptInvite', page: <AcceptInvite />, path: '/accept-invite?token=t1' },
  ])('announces mismatched passwords on $name', ({ page, path }) => {
    mistypeConfirmation(page, path)

    expect(screen.getByRole('alert')).toHaveTextContent('Passwords do not match')
  })
})

describe('auth form autofill', () => {
  it.each([
    { name: 'Signup', page: <Signup />, path: '/signup' },
    { name: 'AcceptInvite', page: <AcceptInvite />, path: '/accept-invite?token=t1' },
  ])('lets a password manager offer a new password for both fields on $name', ({ page, path }) => {
    render(<MemoryRouter initialEntries={[path]}>{page}</MemoryRouter>)

    expect(screen.getByLabelText('Password')).toHaveAttribute('autocomplete', 'new-password')
    expect(screen.getByLabelText('Confirm Password')).toHaveAttribute('autocomplete', 'new-password')
  })
})

describe('auth form navigation', () => {
  it.each([
    { name: 'Signup', page: <Signup />, path: '/signup' },
    { name: 'AcceptInvite', page: <AcceptInvite />, path: '/accept-invite?token=t1' },
  ])('offers the login under the submit on $name', ({ page, path }) => {
    render(<MemoryRouter initialEntries={[path]}>{page}</MemoryRouter>)

    expect(screen.getByText(/Already have an account\?/)).toContainElement(screen.getByRole('link', { name: 'Login' }))
    expect(screen.getByRole('link', { name: 'Login' })).toHaveAttribute('href', '/login')
  })
})

describe('auth form guidance', () => {
  it.each([
    { name: 'Signup', page: <Signup />, path: '/signup' },
    { name: 'AcceptInvite', page: <AcceptInvite />, path: '/accept-invite?token=t1' },
  ])('states the password rule under the password on $name, as the reset page does', ({ page, path }) => {
    render(<MemoryRouter initialEntries={[path]}>{page}</MemoryRouter>)

    expect(screen.getByLabelText('Password').parentElement).toHaveTextContent(
      'Must be at least 8 characters and contain uppercase, lowercase, digit, and special character.',
    )
  })
})

describe('auth card layout', () => {
  it.each([
    { name: 'Login', page: <Login />, path: '/login' },
    { name: 'Signup', page: <Signup />, path: '/signup' },
    { name: 'AcceptInvite', page: <AcceptInvite />, path: '/accept-invite?token=t1' },
    { name: 'ResetPassword', page: <ResetPassword />, path: '/reset-password?token=t1' },
    { name: 'VerifyEmail', page: <VerifyEmail verifyToken={vi.fn()} />, path: '/verify-email' },
    {
      name: 'RequestEmailLink',
      page: <RequestEmailLink title="Forgot Password" description="" submitLabel="Send Reset Email" requestLink={vi.fn()} />,
      path: '/forgot-password',
    },
  ])('keeps the top of the $name card reachable on a screen shorter than the card', ({ page, path }) => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter initialEntries={[path]}>{page}</MemoryRouter>
      </QueryClientProvider>,
    )

    expect(container.firstElementChild).toHaveClass('flex h-screen items-center-safe justify-center bg-muted/50', { exact: true })
  })
})
