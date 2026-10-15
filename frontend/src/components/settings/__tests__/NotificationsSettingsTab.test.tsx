import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { toast } from 'sonner'
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

function renderTab(formData: Partial<SystemSettings> = SLACK_APP) {
  render(
    <NotificationsSettingsTab
      formData={formData}
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
      onUpdateWebhook={vi.fn()}
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

  it('names an install that failed to start and why', async () => {
    getSlackAuthorizeUrl.mockRejectedValue(new Error('Network Error'))
    renderTab()

    fireEvent.click(screen.getByRole('button', { name: 'Connect to Slack Workspace' }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to start the Slack install', { description: 'Network Error' }))
  })

  it('asks to save edited scopes before connecting, since the backend installs the saved ones', () => {
    renderTab({ ...SLACK_APP, slack_oauth_scopes: 'chat:write,im:write' })

    expect(screen.getByText('Please save your changes before connecting to Slack.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Connect to Slack Workspace' })).not.toBeInTheDocument()
    expect(getSlackAuthorizeUrl).not.toHaveBeenCalled()
  })

  it('offers the install after the client secret field is emptied, since an empty secret saves nothing', () => {
    renderTab({ ...SLACK_APP, slack_client_secret: '' })

    expect(screen.getByRole('button', { name: 'Connect to Slack Workspace' })).toBeInTheDocument()
  })

  it('asks to save a pending client secret removal before connecting', () => {
    renderTab({ ...SLACK_APP, slack_client_secret: null })

    expect(screen.getByText('Please save your changes before connecting to Slack.')).toBeInTheDocument()
  })
})

describe('NotificationsSettingsTab - Slack auth modes on a phone', () => {
  it('wraps the OAuth and manual tab labels inside their halves instead of cutting them off', () => {
    renderTab()

    const oauth = screen.getByRole('tab', { name: 'OAuth (Recommended)' })
    expect(oauth).toHaveClass('whitespace-normal')
    expect(screen.getByRole('tab', { name: 'Manual Bot Token' })).toHaveClass('whitespace-normal')
    expect(oauth.parentElement).toHaveClass('h-auto')
  })
})
