import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import ProfilePage from '../Profile'
import { Permissions } from '@/lib/permissions'

const granted = vi.hoisted(() => ({ current: [] as string[] }))

vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({
    hasPermission: (permission: string) => granted.current.includes(permission),
  }),
}))

vi.mock('@/hooks/queries/use-users', () => ({
  useCurrentUser: () => ({ data: { id: 'u-1', username: 'ada' }, isLoading: false }),
}))

vi.mock('@/hooks/queries/use-system', () => ({
  useNotificationChannels: () => ({ data: [] }),
  useAppConfig: () => ({ data: {} }),
}))

// Keep the page test about which key cards appear; stub every card body.
vi.mock('@/components/profile/UserDetailsCard', () => ({ UserDetailsCard: () => null }))
vi.mock('@/components/profile/PasswordUpdateCard', () => ({ PasswordUpdateCard: () => null }))
vi.mock('@/components/profile/TwoFactorAuthCard', () => ({ TwoFactorAuthCard: () => null }))
vi.mock('@/components/profile/NotificationPreferencesCard', () => ({
  NotificationPreferencesCard: () => null,
}))
vi.mock('@/components/profile/ApiKeysCard', () => ({
  ApiKeysCard: () => <div data-testid="card-unified" />,
}))

const UNIFIED = 'card-unified'
const MCP_CARD_HEADING = /MCP API Keys/i
const ADHOC_CARD_HEADING = /Ad-hoc Analysis API Keys/i
const SUPERSEDED_NOTE = /superseded/i
const NONE = 0

function cardOrder(): (string | null)[] {
  return screen.getAllByTestId(/^card-/).map((el) => el.getAttribute('data-testid'))
}

function Providers({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function renderProfile(permissions: string[]) {
  granted.current = permissions
  render(<ProfilePage />, { wrapper: Providers })
}

beforeEach(() => {
  granted.current = []
})

describe('ProfilePage - API key cards', () => {
  it('renders the unified card as the only API key card', () => {
    renderProfile([Permissions.MCP_ACCESS, Permissions.ANALYZE_ADHOC])

    expect(cardOrder()).toEqual([UNIFIED])
  })

  it.each([
    ['MCP access', [Permissions.MCP_ACCESS]],
    ['ad-hoc analysis', [Permissions.ANALYZE_ADHOC]],
  ])('renders the unified card for a user holding only %s', (_label, permissions) => {
    renderProfile(permissions as string[])

    expect(screen.getByTestId(UNIFIED)).toBeInTheDocument()
  })

  // Ownership alone governs listing and revoking, so losing the permission that
  // minted a key must not strand it beyond its owner's reach.
  it('renders the unified card for a user holding neither surface permission', () => {
    renderProfile([])

    expect(screen.getByTestId(UNIFIED)).toBeInTheDocument()
  })

  it('renders no per-surface key card and no superseded note', () => {
    renderProfile([Permissions.MCP_ACCESS, Permissions.ANALYZE_ADHOC])

    expect(screen.queryByText(MCP_CARD_HEADING)).not.toBeInTheDocument()
    expect(screen.queryByText(ADHOC_CARD_HEADING)).not.toBeInTheDocument()
    expect(screen.queryAllByText(SUPERSEDED_NOTE)).toHaveLength(NONE)
  })
})
