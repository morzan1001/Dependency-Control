import { fireEvent, render, screen } from '@testing-library/react'
import { AxiosError, type InternalAxiosRequestConfig } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { authApi } from '@/api/auth'
import { api } from '@/api/client'
import App from '../App'
import { LOGIN_RETURN_KEY } from '../lib/constants'

vi.mock('@/hooks/queries/use-system', () => ({
  usePublicConfig: () => ({ data: { oidc_enabled: true, allow_public_registration: false } }),
  useAppConfig: () => ({ data: undefined }),
}))
vi.mock('@/api/auth', async (importOriginal) => {
  const { authApi: real } = await importOriginal<typeof import('@/api/auth')>()
  return { authApi: { ...real, exchangeOidcLogin: vi.fn(), logout: vi.fn().mockResolvedValue(undefined) } }
})
vi.mock('@/api/users', () => ({ userApi: { getMe: vi.fn().mockResolvedValue({ permissions: ['project:read'] }) } }))
vi.mock('../pages/ScanDetails', () => ({ default: () => <p>scan page</p> }))

const DEEP_LINK = '/projects/p1/scans/s1?tab=raw&sbom=0'

// The signature is never verified client-side.
function sessionToken(permissions: string[]): string {
  const encode = (obj: unknown) => btoa(JSON.stringify(obj)).replace(/=+$/, '')
  return `${encode({ alg: 'HS256' })}.${encode({ sub: 'u1', permissions, type: 'access' })}.sig`
}

const unauthorized = (config: InternalAxiosRequestConfig) =>
  new AxiosError('Unauthorized', AxiosError.ERR_BAD_REQUEST, config, null, {
    data: {},
    status: 401,
    statusText: 'Unauthorized',
    headers: {},
    config,
  })

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
  // next-themes reads the colour-scheme preference, which jsdom does not implement.
  globalThis.matchMedia = vi.fn().mockReturnValue({ matches: false, addListener: vi.fn(), removeListener: vi.fn() })
})

describe('a deep link opened while signed out', () => {
  it('shows the login form and remembers the page it pointed at', async () => {
    globalThis.history.replaceState(null, '', DEEP_LINK)

    render(<App />)

    expect(await screen.findByLabelText('Username')).toBeInTheDocument()
    expect(globalThis.location.pathname).toBe('/login')
    expect(sessionStorage.getItem(LOGIN_RETURN_KEY)).toBe(DEEP_LINK)
  })

  it('opens that page once single sign-on hands the session over', async () => {
    sessionStorage.setItem(LOGIN_RETURN_KEY, DEEP_LINK)
    vi.mocked(authApi.exchangeOidcLogin).mockResolvedValue({
      access_token: sessionToken(['project:read']),
      refresh_token: 'refresh',
      token_type: 'bearer',
    })
    globalThis.history.replaceState(null, '', '/login/callback')

    render(<App />)

    expect(await screen.findByText('scan page')).toBeInTheDocument()
    expect(globalThis.location.pathname + globalThis.location.search).toBe(DEEP_LINK)
  })
})

describe('a session that ends on a page', () => {
  beforeEach(() => {
    localStorage.setItem('token', sessionToken(['project:read']))
    localStorage.setItem('refresh_token', 'refresh')
    globalThis.history.replaceState(null, '', DEEP_LINK)
  })

  it('leaves no page waiting when the user signs out', async () => {
    render(<App />)
    await screen.findByText('scan page')

    fireEvent.click(screen.getByRole('button', { name: 'Logout' }))

    expect(await screen.findByLabelText('Username')).toBeInTheDocument()
    expect(sessionStorage.getItem(LOGIN_RETURN_KEY)).toBeNull()
  })

  it('keeps the page waiting when the session expires', async () => {
    render(<App />)
    await screen.findByText('scan page')
    localStorage.removeItem('refresh_token')

    await api.get('/projects', { adapter: (config) => Promise.reject(unauthorized(config)) }).catch(() => undefined)

    expect(await screen.findByLabelText('Username')).toBeInTheDocument()
    expect(sessionStorage.getItem(LOGIN_RETURN_KEY)).toBe(DEEP_LINK)
  })
})
