import { render, screen } from '@testing-library/react'
import { useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from '../App'

vi.mock('@/hooks/queries/use-system', () => ({
  usePublicConfig: () => ({ data: undefined }),
  useAppConfig: () => ({ data: undefined }),
}))
vi.mock('@/api/users', () => ({ userApi: { getMe: vi.fn().mockResolvedValue({ permissions: ['analytics:read'] }) } }))
vi.mock('../pages/Analytics', () => ({
  default: function AnalyticsStub() {
    const location = useLocation()
    return <p>analytics at {location.pathname + location.search}</p>
  },
}))

function sessionToken(permissions: string[]): string {
  const encode = (obj: unknown) => btoa(JSON.stringify(obj)).replace(/=+$/, '')
  return `${encode({ alg: 'HS256' })}.${encode({ sub: 'u1', permissions, type: 'access' })}.sig`
}

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
  globalThis.matchMedia = vi.fn().mockReturnValue({ matches: false, addListener: vi.fn(), removeListener: vi.fn() })
  localStorage.setItem('token', sessionToken(['analytics:read']))
  localStorage.setItem('refresh_token', 'refresh')
})

describe('the legacy dependency search link', () => {
  it('opens the Dependencies tab of Analytics', async () => {
    globalThis.history.replaceState(null, '', '/search/dependencies')

    render(<App />)

    expect(await screen.findByText('analytics at /analytics?tab=search-deps')).toBeInTheDocument()
  })
})
