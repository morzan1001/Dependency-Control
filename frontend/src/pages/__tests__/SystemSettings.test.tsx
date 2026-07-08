import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import SystemSettings from '../SystemSettings'
import { systemKeys } from '@/hooks/queries/use-system'
import type { SystemSettings as SystemSettingsType } from '@/types/system'

vi.mock('sonner', () => ({
  toast: { error: vi.fn(), success: vi.fn() },
}))

vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ hasPermission: () => true }),
}))

const mockUseSystemSettings = vi.fn()
const mockMutate = vi.fn()
vi.mock('@/hooks/queries/use-system', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/hooks/queries/use-system')>()
  return {
    ...actual,
    useSystemSettings: () => mockUseSystemSettings(),
    useUpdateSystemSettings: () => ({ mutate: mockMutate, isPending: false }),
    useAppConfig: () => ({ data: { chat_enabled: false } }),
  }
})

vi.mock('@/hooks/queries/use-webhooks', () => ({
  useGlobalWebhooks: () => ({ data: [], isLoading: false }),
  useCreateGlobalWebhook: () => ({ mutateAsync: vi.fn() }),
  useDeleteWebhook: () => ({ mutateAsync: vi.fn() }),
}))

vi.mock('@/components/settings', () => {
  const Tab = ({
    formData,
    handleSave,
  }: {
    formData: Partial<SystemSettingsType>
    handleSave: () => void
  }) => (
    <div>
      <span data-testid="slack-token">{formData.slack_bot_token ?? ''}</span>
      <button onClick={handleSave}>Save</button>
    </div>
  )
  return {
    GeneralSettingsTab: Tab,
    SecuritySettingsTab: Tab,
    NotificationsSettingsTab: Tab,
    IntegrationsSettingsTab: Tab,
    ChatSettingsTab: Tab,
    CryptoPolicySettingsTab: () => null,
  }
})

function makeSettings(overrides: Partial<SystemSettingsType> = {}): SystemSettingsType {
  return {
    project_limit_per_user: 10,
    allow_public_registration: false,
    retention_mode: 'global',
    global_retention_days: 90,
    global_retention_action: 'delete',
    rescan_mode: 'global',
    global_rescan_enabled: true,
    global_rescan_interval: 7,
    crypto_policy_mode: 'global',
    ...overrides,
  }
}

function renderPage(initialEntries: string[] = ['/settings']) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const invalidateSpy = vi.spyOn(client, 'invalidateQueries')
  const utils = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <SystemSettings />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return { ...utils, invalidateSpy }
}

beforeEach(() => {
  mockUseSystemSettings.mockReset()
  mockMutate.mockReset()
})

describe('SystemSettings - Slack connect refresh', () => {
  it('invalidates the real settings query key on slack_connected redirect', async () => {
    mockUseSystemSettings.mockReturnValue({
      data: makeSettings({ slack_bot_token: 'old' }),
      isLoading: false,
    })

    const { invalidateSpy } = renderPage(['/settings?slack_connected=true'])

    await waitFor(() => {
      expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: systemKeys.settings() })
    })
    expect(invalidateSpy).not.toHaveBeenCalledWith({ queryKey: ['systemSettings'] })
  })

  it('re-syncs formData when the settings query returns fresh data so Save cannot submit a stale snapshot', () => {
    mockUseSystemSettings.mockReturnValue({
      data: makeSettings({ slack_bot_token: 'old' }),
      isLoading: false,
    })

    const { rerender } = renderPage()
    expect(screen.getByTestId('slack-token')).toHaveTextContent('old')

    // Server settings changed (e.g. after the OAuth round-trip stored new tokens).
    mockUseSystemSettings.mockReturnValue({
      data: makeSettings({ slack_bot_token: 'new' }),
      isLoading: false,
    })
    rerender(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <SystemSettings />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    expect(screen.getByTestId('slack-token')).toHaveTextContent('new')

    fireEvent.click(screen.getByText('Save'))
    expect(mockMutate).toHaveBeenCalledWith(
      expect.objectContaining({ slack_bot_token: 'new' }),
      expect.anything(),
    )
  })
})
