import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route, useNavigate } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { AuthProvider } from '../AuthProvider'
import { useAuth } from '../useAuth'

vi.mock('@/api/users', () => ({
  userApi: {
    getMe: vi.fn(),
  },
}))

vi.mock('@/api/client', () => ({
  setLogoutCallback: vi.fn(),
}))

import { userApi } from '@/api/users'

const getMe = userApi.getMe as unknown as ReturnType<typeof vi.fn>

// jsdom in this harness may lack a working localStorage; install an in-memory one.
if (typeof globalThis.localStorage === 'undefined' || globalThis.localStorage === null) {
  const store = new Map<string, string>()
  const mem: Storage = {
    get length() {
      return store.size
    },
    clear: () => store.clear(),
    getItem: (k: string) => (store.has(k) ? (store.get(k) as string) : null),
    key: (i: number) => Array.from(store.keys())[i] ?? null,
    removeItem: (k: string) => {
      store.delete(k)
    },
    setItem: (k: string, v: string) => {
      store.set(k, String(v))
    },
  }
  Object.defineProperty(globalThis, 'localStorage', { value: mem, configurable: true })
}

// Minimal valid JWT for jwt-decode; the signature is never verified client-side.
function makeToken(permissions: string[]): string {
  const now = Math.floor(Date.now() / 1000)
  const encode = (obj: unknown) =>
    btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const header = encode({ alg: 'HS256', typ: 'JWT' })
  const payload = encode({
    exp: now + 3600,
    iat: now,
    sub: 'user-1',
    permissions,
    type: 'access',
  })
  return `${header}.${payload}.sig`
}

// The button triggers navigation, which changes react-router's `navigate` identity.
function AuthProbe() {
  const { isAuthenticated, isLoading } = useAuth()
  const navigate = useNavigate()
  return (
    <div>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="authed">{String(isAuthenticated)}</span>
      <button onClick={() => navigate('/projects')}>go</button>
    </div>
  )
}

function renderApp() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <AuthProvider>
        <Routes>
          <Route path="/dashboard" element={<AuthProbe />} />
          <Route path="/projects" element={<AuthProbe />} />
          <Route path="/login" element={<div data-testid="login-page">login</div>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('AuthProvider init effect', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('does not re-run getMe or drop auth when navigating between routes', async () => {
    localStorage.setItem('token', makeToken(['read']))
    localStorage.setItem('refresh_token', 'refresh')

    // Only the mount call resolves; a later failure matters only if the effect re-fires.
    getMe.mockResolvedValueOnce({ id: 'user-1' })
    getMe.mockRejectedValue(new Error('transient 500'))

    renderApp()

    await waitFor(() => {
      expect(screen.getByTestId('authed').textContent).toBe('true')
    })
    expect(getMe).toHaveBeenCalledTimes(1)

    // Navigate away, changing navigate/logout identity.
    fireEvent.click(screen.getByText('go'))

    await waitFor(() => {
      expect(screen.getByText('go')).toBeInTheDocument()
    })

    expect(getMe).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('authed').textContent).toBe('true')
    expect(screen.queryByTestId('login-page')).not.toBeInTheDocument()
  })

  it('sets unauthenticated when no token is present', async () => {
    renderApp()
    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false')
    })
    expect(screen.getByTestId('authed').textContent).toBe('false')
    expect(getMe).not.toHaveBeenCalled()
  })
})
