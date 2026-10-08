import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import ProfilePage from '../Profile'
import { systemApi } from '@/api/system'
import { useUpdateSystemSettings } from '@/hooks/queries/use-system'
import type { AppConfig } from '@/types/system'

vi.mock('@/api/system', () => ({
  systemApi: { getAppConfig: vi.fn(), updateSettings: vi.fn() },
}))
vi.mock('@/hooks/queries/use-users', () => ({
  useCurrentUser: () => ({ data: { id: 'u-1', username: 'ada' }, isLoading: false }),
}))
vi.mock('@/components/profile/UserDetailsCard', () => ({
  UserDetailsCard: ({ notificationChannels }: { notificationChannels?: string[] }) => (
    <p>channels: {notificationChannels?.join(',')}</p>
  ),
}))
vi.mock('@/components/profile/PasswordUpdateCard', () => ({ PasswordUpdateCard: () => null }))
vi.mock('@/components/profile/TwoFactorAuthCard', () => ({ TwoFactorAuthCard: () => null }))
vi.mock('@/components/profile/NotificationPreferencesCard', () => ({ NotificationPreferencesCard: () => null }))
vi.mock('@/components/profile/ApiKeysCard', () => ({ ApiKeysCard: () => null }))

function appConfig(slack: boolean): AppConfig {
  return {
    archive_enabled: false,
    retention_mode: 'project',
    global_retention_days: 90,
    global_retention_action: 'delete',
    rescan_mode: 'project',
    global_rescan_enabled: false,
    global_rescan_interval: 7,
    notifications: { email: true, slack, mattermost: false },
    default_project_analyzers: [],
  }
}

function SaveSettings() {
  const update = useUpdateSystemSettings()
  return <button onClick={() => update.mutate({ slack_bot_token: 'xoxb-new' })}>save</button>
}

describe('ProfilePage notification channels', () => {
  it('offers a channel an admin configured in the same session', async () => {
    vi.mocked(systemApi.getAppConfig).mockResolvedValueOnce(appConfig(false)).mockResolvedValue(appConfig(true))
    vi.mocked(systemApi.updateSettings).mockResolvedValue({} as Awaited<ReturnType<typeof systemApi.updateSettings>>)
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <ProfilePage />
        <SaveSettings />
      </QueryClientProvider>,
    )
    expect(await screen.findByText('channels: email')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'save' }))

    expect(await screen.findByText('channels: email,slack')).toBeInTheDocument()
  })
})
