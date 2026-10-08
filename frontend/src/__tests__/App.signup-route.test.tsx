import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const getPublicConfig = vi.hoisted(() => vi.fn())
vi.mock('@/api/system', () => ({ systemApi: { getPublicConfig } }))

const OPEN = { allow_public_registration: true, oidc_enabled: false }
const CLOSED = { allow_public_registration: false, oidc_enabled: false }

// App holds its QueryClient at module level, so each test loads a fresh copy.
async function renderAppAt(path: string) {
  vi.resetModules()
  globalThis.history.replaceState(null, '', path)
  const { default: App } = await import('../App')
  render(<App />)
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  sessionStorage.clear()
  globalThis.matchMedia = vi.fn().mockReturnValue({ matches: false, addListener: vi.fn(), removeListener: vi.fn() })
})

describe('the sign-up route', () => {
  it('opens the sign-up form while public registration is on', async () => {
    getPublicConfig.mockResolvedValue(OPEN)

    await renderAppAt('/signup')

    expect(await screen.findByText('Create Account')).toBeInTheDocument()
  })

  it('sends the visitor to the login form while public registration is off', async () => {
    getPublicConfig.mockResolvedValue(CLOSED)

    await renderAppAt('/signup')

    expect(await screen.findByRole('button', { name: 'Login' })).toBeInTheDocument()
    expect(globalThis.location.pathname).toBe('/login')
  })

  it('sends the visitor to the login form when the configuration cannot be read', async () => {
    getPublicConfig.mockRejectedValue(new Error('Network Error'))

    await renderAppAt('/signup')

    expect(await screen.findByRole('button', { name: 'Login' }, { timeout: 4000 })).toBeInTheDocument()
    expect(globalThis.location.pathname).toBe('/login')
  })

  it('reuses the configuration the login page already read', async () => {
    getPublicConfig.mockResolvedValue(OPEN)
    await renderAppAt('/login')

    fireEvent.click(await screen.findByRole('link', { name: 'Sign Up' }))

    expect(await screen.findByText('Create Account')).toBeInTheDocument()
    expect(getPublicConfig).toHaveBeenCalledTimes(1)
  })
})
