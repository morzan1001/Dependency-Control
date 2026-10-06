import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { MemoryRouter, Routes, Route } from 'react-router-dom'

import LoginCallback from '../LoginCallback'
import Login from '../Login'

const login = vi.fn()
const exchangeOidcLogin = vi.fn()

vi.mock('@/hooks/queries/use-auth', () => ({
  useLogin: () => ({ mutate: vi.fn(), isPending: false }),
}))

vi.mock('@/hooks/queries/use-system', () => ({
  usePublicConfig: () => ({ data: { oidc_enabled: false } }),
}))

vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ login, isAuthenticated: false }),
}))

vi.mock('@/api/auth', () => ({
  authApi: { exchangeOidcLogin: () => exchangeOidcLogin() },
}))

const originalHash = globalThis.location.hash

function renderCallbackFlow() {
  return render(
    <MemoryRouter initialEntries={['/login/callback']}>
      <Routes>
        <Route path="/login/callback" element={<LoginCallback />} />
        <Route path="/login" element={<Login />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  globalThis.location.hash = originalHash
})

describe('LoginCallback', () => {
  it('collects the session the server left for this browser', async () => {
    exchangeOidcLogin.mockResolvedValue({ access_token: 'a', refresh_token: 'r', token_type: 'bearer' })

    renderCallbackFlow()

    await waitFor(() => expect(login).toHaveBeenCalledWith('a', 'r'))
    expect(exchangeOidcLogin).toHaveBeenCalledTimes(1)
  })

  it('ignores tokens planted in the link', async () => {
    globalThis.location.hash = '#access_token=planted&refresh_token=planted'
    exchangeOidcLogin.mockRejectedValue(new Error('400'))

    renderCallbackFlow()

    expect(await screen.findByText('Single sign-on failed. Please try again.')).toBeInTheDocument()
    expect(login).not.toHaveBeenCalled()
  })

  it('explains a known failure code without asking the server', async () => {
    globalThis.location.hash = '#error=not_provisioned'

    renderCallbackFlow()

    expect(await screen.findByText(/No account exists for you yet/)).toBeInTheDocument()
    expect(exchangeOidcLogin).not.toHaveBeenCalled()
  })

  it('shows only its own text for a code it does not know', async () => {
    globalThis.location.hash = '#error=Your%20account%20is%20locked%2C%20call%20555-0100'

    renderCallbackFlow()

    expect(await screen.findByText('Single sign-on failed. Please try again.')).toBeInTheDocument()
    expect(screen.queryByText(/555-0100/)).not.toBeInTheDocument()
  })
})
