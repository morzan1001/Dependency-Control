import { render, screen } from '@testing-library/react'
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

// Keep the page test about which key cards appear and in what order; stub every card body.
vi.mock('@/components/profile/UserDetailsCard', () => ({ UserDetailsCard: () => null }))
vi.mock('@/components/profile/PasswordUpdateCard', () => ({ PasswordUpdateCard: () => null }))
vi.mock('@/components/profile/TwoFactorAuthCard', () => ({ TwoFactorAuthCard: () => null }))
vi.mock('@/components/profile/NotificationPreferencesCard', () => ({
  NotificationPreferencesCard: () => null,
}))
vi.mock('@/components/profile/ApiKeysCard', () => ({
  ApiKeysCard: () => <div data-testid="card-unified" />,
}))
vi.mock('@/components/profile/MCPApiKeysCard', () => ({
  MCPApiKeysCard: () => <div data-testid="card-mcp" />,
}))
vi.mock('@/components/profile/AdhocApiKeysCard', () => ({
  AdhocApiKeysCard: () => <div data-testid="card-adhoc" />,
}))

const UNIFIED = 'card-unified'
const MCP = 'card-mcp'
const ADHOC = 'card-adhoc'
const SUPERSEDED_NOTE = /superseded/i
const NONE = 0

function cardOrder(): (string | null)[] {
  return screen.getAllByTestId(/^card-/).map((el) => el.getAttribute('data-testid'))
}

function renderProfile(permissions: string[]) {
  granted.current = permissions
  render(<ProfilePage />)
}

beforeEach(() => {
  granted.current = []
})

describe('ProfilePage - API key cards', () => {
  it('renders the unified card above both legacy cards', () => {
    renderProfile([Permissions.MCP_ACCESS, Permissions.ANALYZE_ADHOC])

    expect(cardOrder()).toEqual([UNIFIED, MCP, ADHOC])
  })

  it.each([
    ['MCP only', [Permissions.MCP_ACCESS], MCP, ADHOC],
    ['ad-hoc only', [Permissions.ANALYZE_ADHOC], ADHOC, MCP],
  ])(
    'renders the unified card for a user holding %s',
    (_label, permissions, presentLegacy, absentLegacy) => {
      renderProfile(permissions as string[])

      expect(screen.getByTestId(UNIFIED)).toBeInTheDocument()
      expect(screen.getByTestId(presentLegacy as string)).toBeInTheDocument()
      expect(screen.queryByTestId(absentLegacy as string)).not.toBeInTheDocument()
    },
  )

  it('renders the unified card for a user holding neither surface permission', () => {
    renderProfile([])

    expect(screen.getByTestId(UNIFIED)).toBeInTheDocument()
    expect(screen.queryByTestId(MCP)).not.toBeInTheDocument()
    expect(screen.queryByTestId(ADHOC)).not.toBeInTheDocument()
  })

  it('keeps each legacy card behind its own surface permission', () => {
    renderProfile([Permissions.MCP_ACCESS])

    expect(cardOrder()).toEqual([UNIFIED, MCP])
  })

  it('announces the legacy cards as superseded above them, without calling their keys dead', () => {
    renderProfile([Permissions.MCP_ACCESS, Permissions.ANALYZE_ADHOC])

    const note = screen.getByText(SUPERSEDED_NOTE)
    expect(note.compareDocumentPosition(screen.getByTestId(MCP))).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    )
    expect(note.compareDocumentPosition(screen.getByTestId(UNIFIED))).toBe(
      Node.DOCUMENT_POSITION_PRECEDING,
    )
  })

  it('omits the superseded note when no legacy card is rendered', () => {
    renderProfile([])

    expect(screen.queryAllByText(SUPERSEDED_NOTE)).toHaveLength(NONE)
  })
})
