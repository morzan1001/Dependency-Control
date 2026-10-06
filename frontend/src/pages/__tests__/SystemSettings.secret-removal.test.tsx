import { fireEvent, render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { SystemSettings as SystemSettingsType } from '@/types/system'

import SystemSettings from '../SystemSettings'

const { mutate } = vi.hoisted(() => ({ mutate: vi.fn() }))

vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ hasPermission: () => true }) }))
vi.mock('@/components/settings/CICDInstancesManagement', () => ({ CICDInstancesManagement: () => null }))
vi.mock('@/hooks/queries/use-webhooks', () => ({
  useGlobalWebhooks: () => ({ data: [], isLoading: false }),
  useCreateGlobalWebhook: () => ({ mutateAsync: vi.fn() }),
  useDeleteWebhook: () => ({ mutateAsync: vi.fn() }),
}))

// GET /system/settings never echoes a secret, only whether one is stored.
const SETTINGS: SystemSettingsType = {
  project_limit_per_user: 0,
  allow_public_registration: false,
  retention_mode: 'project',
  global_retention_days: 90,
  global_retention_action: 'delete',
  rescan_mode: 'project',
  global_rescan_enabled: false,
  global_rescan_interval: 24,
  crypto_policy_mode: 'project',
  default_active_analyzers: [],
  github_token_configured: true,
  open_source_malware_api_key_configured: true,
}

vi.mock('@/hooks/queries/use-system', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/queries/use-system')>()),
  useSystemSettings: () => ({ data: SETTINGS, isLoading: false }),
  useUpdateSystemSettings: () => ({ mutate, isPending: false }),
  useAppConfig: () => ({ data: { chat_enabled: false } }),
}))

describe('SystemSettings stored secrets', () => {
  beforeEach(() => vi.clearAllMocks())

  it('sends null for a removed secret and leaves the other stored secrets out', () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <SystemSettings />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    // Radix selects a tab on mousedown.
    fireEvent.mouseDown(screen.getByRole('tab', { name: 'Integrations' }))

    const githubToken = screen.getByLabelText('GitHub Personal Access Token').parentElement as HTMLElement
    fireEvent.click(within(githubToken).getByRole('button', { name: 'Remove' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save External Integrations' }))

    const payload = mutate.mock.calls[0][0]
    expect(payload).toHaveProperty('github_token', null)
    expect(payload).not.toHaveProperty('open_source_malware_api_key')
  })
})
