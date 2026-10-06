import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { AxiosError, type InternalAxiosRequestConfig } from 'axios'
import { MemoryRouter, Navigate, Routes, Route, useNavigate } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { api } from '@/api/client'

import { AuthProvider } from '../AuthProvider'
import { useAuth } from '../useAuth'

vi.mock('@/api/users', () => ({
  userApi: {
    getMe: vi.fn(),
  },
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
function makeToken(permissions: string[], sub = 'user-1'): string {
  const now = Math.floor(Date.now() / 1000)
  const encode = (obj: unknown) =>
    btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const header = encode({ alg: 'HS256', typ: 'JWT' })
  const payload = encode({
    exp: now + 3600,
    iat: now,
    sub,
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

function PermissionsProbe() {
  const { permissions, isLoading } = useAuth()
  return <span data-testid="permissions">{isLoading ? '' : permissions.join(',')}</span>
}

function renderApp(routes: React.ReactNode, queryClient = new QueryClient()) {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/dashboard']}>
        <AuthProvider>
          <Routes>{routes}</Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const probeRoutes = (
  <>
    <Route path="/dashboard" element={<AuthProbe />} />
    <Route path="/projects" element={<AuthProbe />} />
    <Route path="/login" element={<div data-testid="login-page">login</div>} />
  </>
)

let sentRequests: { method?: string; url?: string; authorization: unknown }[] = []

// Answers every request with the bearer it carried, so cached data reveals whose session fetched it.
function stubBackend(failLogout?: (config: InternalAxiosRequestConfig) => Error) {
  sentRequests = []
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    const authorization = config.headers.Authorization
    sentRequests.push({ method: config.method, url: config.url, authorization })
    // Ends a 401 -> logout -> 401 loop, so it fails an assertion instead of starving the event loop.
    if (sentRequests.length > 20) throw networkError()
    if (!authorization) throw httpError(config, 401, 'Unauthorized')
    if (failLogout && config.url === '/logout') throw failLogout(config)
    return { data: { owner: authorization }, status: 200, statusText: 'OK', headers: {}, config }
  }
}

const httpError = (config: InternalAxiosRequestConfig, status: number, statusText: string) =>
  new AxiosError(`Request failed with status code ${status}`, AxiosError.ERR_BAD_RESPONSE, config, null, {
    data: {},
    status,
    statusText,
    headers: {},
    config,
  })
const serverError = (config: InternalAxiosRequestConfig) => httpError(config, 500, 'Internal Server Error')
const networkError = () => new Error('Network Error')

function Projects() {
  const { logout } = useAuth()
  const { data } = useQuery({
    queryKey: ['projects'],
    queryFn: async () => (await api.get<{ owner: string }>('/projects')).data,
  })
  return (
    <div>
      <span data-testid="owner">{data?.owner ?? ''}</span>
      <button onClick={logout}>logout</button>
    </div>
  )
}

function ProtectedProjects() {
  const { isAuthenticated, isLoading } = useAuth()
  if (isLoading) return null
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <Projects />
}

function LoginAs({ token }: Readonly<{ token: string }>) {
  const { login } = useAuth()
  return <button onClick={() => login(token, 'refresh-2')}>login</button>
}

function renderSession(nextUserToken: string, queryClient: QueryClient) {
  return renderApp(
    <>
      <Route path="/dashboard" element={<ProtectedProjects />} />
      <Route path="/login" element={<LoginAs token={nextUserToken} />} />
    </>,
    queryClient,
  )
}

// Mirrors the 5-minute staleTime of the app's user and project queries.
const sessionQueryClient = () =>
  new QueryClient({ defaultOptions: { queries: { staleTime: 5 * 60 * 1000, retry: false } } })

describe('AuthProvider init effect', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('does not re-run getMe or drop auth when navigating between routes', async () => {
    localStorage.setItem('token', makeToken(['read']))
    localStorage.setItem('refresh_token', 'refresh')

    // Only the mount call resolves; a later failure matters only if the effect re-fires.
    getMe.mockResolvedValueOnce({ id: 'user-1', permissions: ['read'] })
    getMe.mockRejectedValue(new Error('transient 500'))

    renderApp(probeRoutes)

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

  it('takes the permissions from the server rather than from the stored token', async () => {
    // The token predates an admin's change: user:read_all was revoked and project:read granted since.
    localStorage.setItem('token', makeToken(['user:read_all']))
    localStorage.setItem('refresh_token', 'refresh')
    getMe.mockResolvedValue({ id: 'user-1', permissions: ['project:read'] })

    renderApp(<Route path="/dashboard" element={<PermissionsProbe />} />)

    await waitFor(() => expect(screen.getByTestId('permissions').textContent).toBe('project:read'))
  })

  it('sets unauthenticated when no token is present', async () => {
    renderApp(probeRoutes)
    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false')
    })
    expect(screen.getByTestId('authed').textContent).toBe('false')
    expect(getMe).not.toHaveBeenCalled()
  })
})

describe('AuthProvider logout', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    stubBackend()
    getMe.mockResolvedValue({ id: 'user-1', permissions: ['read'] })
  })

  it('revokes the server session with the session token', async () => {
    const token = makeToken(['read'])
    localStorage.setItem('token', token)
    localStorage.setItem('refresh_token', 'refresh')

    renderSession(makeToken(['read'], 'user-2'), sessionQueryClient())
    await screen.findByText(`Bearer ${token}`)

    fireEvent.click(screen.getByText('logout'))
    await screen.findByText('login')

    expect(sentRequests).toContainEqual({ method: 'post', url: '/logout', authorization: `Bearer ${token}` })
    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('refresh_token')).toBeNull()
  })

  it.each([
    ['a server error', serverError],
    ['a network failure', networkError],
  ])('signs out locally when the revoke fails with %s', async (_, failure) => {
    stubBackend(failure)
    localStorage.setItem('token', makeToken(['read']))
    localStorage.setItem('refresh_token', 'refresh')
    const queryClient = sessionQueryClient()

    renderSession(makeToken(['read'], 'user-2'), queryClient)
    await screen.findByText(/^Bearer /)

    fireEvent.click(screen.getByText('logout'))
    await screen.findByText('login')

    expect(sentRequests.map((r) => r.url)).toContain('/logout')
    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('refresh_token')).toBeNull()
    expect(queryClient.getQueryData(['projects'])).toBeUndefined()
  })

  it('sends no revoke once a rejected refresh has removed the tokens', async () => {
    localStorage.setItem('token', makeToken(['read']))
    localStorage.setItem('refresh_token', 'refresh')

    renderSession(makeToken(['read'], 'user-2'), sessionQueryClient())
    await screen.findByText(/^Bearer /)

    localStorage.clear()
    fireEvent.click(screen.getByText('logout'))
    await screen.findByText('login')
    await new Promise((resolve) => setTimeout(resolve, 0))

    expect(sentRequests.filter((r) => r.url === '/logout')).toHaveLength(0)
  })

  it("empties the query cache so the next login fetches its own data", async () => {
    const firstUser = makeToken(['read'])
    const secondUser = makeToken(['read'], 'user-2')
    localStorage.setItem('token', firstUser)
    localStorage.setItem('refresh_token', 'refresh')
    const queryClient = sessionQueryClient()

    renderSession(secondUser, queryClient)
    await screen.findByText(`Bearer ${firstUser}`)

    fireEvent.click(screen.getByText('logout'))
    await screen.findByText('login')
    expect(queryClient.getQueryData(['projects'])).toBeUndefined()

    fireEvent.click(screen.getByText('login'))
    expect(await screen.findByText(`Bearer ${secondUser}`)).toBeInTheDocument()
    expect(sentRequests.filter((r) => r.url === '/projects').map((r) => r.authorization)).toEqual([
      `Bearer ${firstUser}`,
      `Bearer ${secondUser}`,
    ])
  })
})
