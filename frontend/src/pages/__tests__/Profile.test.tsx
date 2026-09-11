import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'

import ProfilePage from '../Profile'

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
const SUPERSEDED_NOTE = /superseded/i
const NONE = 0

function cardOrder(): (string | null)[] {
  return screen.getAllByTestId(/^card-/).map((el) => el.getAttribute('data-testid'))
}

describe('ProfilePage - API key cards', () => {
  it('renders the unified card as the only API key card', () => {
    render(<ProfilePage />)

    expect(cardOrder()).toEqual([UNIFIED])
  })

  it('renders no superseded note beside the card', () => {
    render(<ProfilePage />)

    expect(screen.queryAllByText(SUPERSEDED_NOTE)).toHaveLength(NONE)
  })
})
