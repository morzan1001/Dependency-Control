import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { User } from '@/types/user'

import { UserDetailsCard } from '../UserDetailsCard'

const { updateMe, requestEmailChange } = vi.hoisted(() => ({
  updateMe: vi.fn(),
  requestEmailChange: vi.fn(),
}))

vi.mock('@/api/users', () => ({ userApi: { updateMe, requestEmailChange } }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const NEW_EMAIL = 'lena.new@corp.com'
const LOCAL_USER: User = {
  id: 'u-lena',
  username: 'lena',
  email: 'lena@corp.com',
  is_active: true,
  auth_provider: 'local',
  permissions: [],
  totp_enabled: false,
}
const IDP_USER: User = { ...LOCAL_USER, id: 'u-otto', username: 'otto', email: 'otto@corp.com', auth_provider: 'gitlab' }

function renderCard(user: User) {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <UserDetailsCard user={user} notificationChannels={['slack']} />
    </QueryClientProvider>,
  )
}

describe('UserDetailsCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows the username read-only and saves the profile without identity fields', async () => {
    updateMe.mockResolvedValue(LOCAL_USER)
    renderCard(LOCAL_USER)

    expect(screen.getByLabelText('Username')).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Slack Member ID'), { target: { value: 'U123' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(updateMe).toHaveBeenCalledTimes(1))
    expect(updateMe.mock.calls[0][0]).toEqual({ slack_username: 'U123', mattermost_username: undefined })
  })

  it('keeps the email of an identity-provider account read-only', () => {
    renderCard(IDP_USER)

    expect(screen.getByLabelText('Email')).toBeDisabled()
    expect(screen.getByText('Managed by your identity provider.')).toBeInTheDocument()
    expect(screen.queryByLabelText('New email')).not.toBeInTheDocument()
  })

  it('sends a confirmation link to the new address of a local account', async () => {
    requestEmailChange.mockResolvedValue({ ...LOCAL_USER, pending_email: NEW_EMAIL })
    renderCard(LOCAL_USER)

    expect(screen.getByLabelText('Email')).toBeDisabled()
    fireEvent.change(screen.getByLabelText('New email'), { target: { value: NEW_EMAIL } })
    fireEvent.click(screen.getByRole('button', { name: 'Send confirmation link' }))

    await waitFor(() => expect(requestEmailChange).toHaveBeenCalledTimes(1))
    expect(requestEmailChange.mock.calls[0][0]).toBe(NEW_EMAIL)
    expect(updateMe).not.toHaveBeenCalled()
  })

  it('shows a pending change while the current address stays in place', () => {
    renderCard({ ...LOCAL_USER, pending_email: NEW_EMAIL })

    expect(screen.getByLabelText('Email')).toHaveValue('lena@corp.com')
    expect(screen.getByText(NEW_EMAIL)).toBeInTheDocument()
    expect(screen.getByText(/waiting for confirmation/i)).toBeInTheDocument()
  })

  it('offers no pending notice when nothing is pending', () => {
    renderCard(LOCAL_USER)

    expect(screen.queryByText(/waiting for confirmation/i)).not.toBeInTheDocument()
  })
})
