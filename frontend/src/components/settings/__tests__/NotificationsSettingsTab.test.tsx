import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { NotificationsSettingsTab } from '../NotificationsSettingsTab'
import type { SystemSettings } from '@/types/system'

const { getSlackAuthorizeUrl } = vi.hoisted(() => ({ getSlackAuthorizeUrl: vi.fn() }))

vi.mock('@/api/system', () => ({ systemApi: { getSlackAuthorizeUrl } }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/components/WebhookManager', () => ({ WebhookManager: () => null }))

const INSTALL_URL = 'https://slack.com/oauth/v2/authorize?client_id=client-1&state=signed'
const SLACK_APP: Partial<SystemSettings> = {
  slack_client_id: 'client-1',
  slack_client_secret_configured: true,
  slack_oauth_scopes: 'chat:write',
}

function renderTab() {
  render(
    <NotificationsSettingsTab
      formData={SLACK_APP}
      handleInputChange={vi.fn()}
      handleSave={vi.fn()}
      hasPermission={() => true}
      isPending={false}
      slackAuthMode="oauth"
      setSlackAuthMode={vi.fn()}
      settings={SLACK_APP as SystemSettings}
      webhooks={[]}
      isLoadingWebhooks={false}
      onCreateWebhook={vi.fn()}
      onDeleteWebhook={vi.fn()}
    />,
  )
}

describe('NotificationsSettingsTab - Slack install', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends the admin to the install URL the backend signed', async () => {
    const location = { href: '', origin: 'https://dc.example.com' }
    vi.stubGlobal('location', location)
    getSlackAuthorizeUrl.mockResolvedValue(INSTALL_URL)
    renderTab()

    fireEvent.click(screen.getByRole('button', { name: 'Connect to Slack Workspace' }))

    await waitFor(() => expect(location.href).toBe(INSTALL_URL))
  })
})
