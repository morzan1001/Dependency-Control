import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { User } from '@/types/user'

import { UserDetailsCard } from '../UserDetailsCard'

const { updateMe, changeEmail } = vi.hoisted(() => ({
  updateMe: vi.fn(),
  changeEmail: vi.fn(),
}))

vi.mock('@/api/users', () => ({ userApi: { updateMe, changeEmail } }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const NEW_EMAIL = 'lena.new@corp.com'
const PENDING_NOTICE = `Open the link sent to ${NEW_EMAIL} to confirm the change. Until then, lena@corp.com stays your address.`
const REFUSAL = 'Email verification is required, but no mail server is configured to confirm a new address'
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

function renderCard(user: User, notificationChannels = ['slack']) {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  const card = (shown: User) => (
    <QueryClientProvider client={client}>
      <UserDetailsCard user={shown} notificationChannels={notificationChannels} />
    </QueryClientProvider>
  )
  const { rerender } = render(card(user))
  return { showRefetched: (refetched: User) => rerender(card(refetched)) }
}

describe('UserDetailsCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('saves the chat IDs without the username', async () => {
    updateMe.mockResolvedValue(LOCAL_USER)
    renderCard(LOCAL_USER)

    fireEvent.change(screen.getByLabelText('Slack Member ID'), { target: { value: 'U123' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save chat IDs' }))

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Chat IDs saved'))
    expect(updateMe).toHaveBeenCalledTimes(1)
    expect(updateMe.mock.calls[0][0]).toEqual({ slack_username: 'U123', mattermost_username: null })
  })

  it('offers the chat ID save beside a Mattermost field alone', () => {
    renderCard(LOCAL_USER, ['email', 'mattermost'])

    expect(screen.getByRole('button', { name: 'Save chat IDs' })).toBeInTheDocument()
  })

  it('offers only the field saves while no chat channel is configured', () => {
    renderCard(LOCAL_USER, ['email'])

    expect(screen.getAllByRole('button').map((button) => button.getAttribute('aria-label'))).toEqual([
      'Save username',
      'Save email',
    ])
  })

  it('renames a local account and tells it to sign in with the new name', async () => {
    updateMe.mockResolvedValue({ ...LOCAL_USER, username: 'lena.k' })
    renderCard(LOCAL_USER)
    const save = screen.getByRole('button', { name: 'Save username' })

    expect(save).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: ' lena.k ' } })
    fireEvent.click(save)

    await waitFor(() => expect(updateMe).toHaveBeenCalledTimes(1))
    expect(updateMe.mock.calls[0][0]).toEqual({ username: 'lena.k' })
    expect(await screen.findByRole('status')).toHaveTextContent('You now sign in as lena.k.')
  })

  it('confirms the rename of an identity-provider account without a sign-in note', async () => {
    updateMe.mockResolvedValue({ ...IDP_USER, username: 'otto.k' })
    renderCard(IDP_USER)

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'otto.k' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save username' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Username changed.')
    expect(screen.queryByText(/sign in as/i)).not.toBeInTheDocument()
  })

  it('shows under the field why a new name was refused', async () => {
    updateMe.mockRejectedValue({ response: { data: { detail: 'Username already taken' } } })
    renderCard(LOCAL_USER)

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'otto' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save username' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Username already taken')
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'otto2' } })
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('offers no save while the name is unchanged or blank', () => {
    renderCard(LOCAL_USER)
    const save = screen.getByRole('button', { name: 'Save username' })

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: ' lena ' } })
    expect(save).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: '   ' } })
    expect(save).toBeDisabled()
  })

  it('removes a stored Slack member ID when the field is emptied', async () => {
    updateMe.mockResolvedValue(LOCAL_USER)
    renderCard({ ...LOCAL_USER, slack_username: 'U123' })

    fireEvent.change(screen.getByLabelText('Slack Member ID'), { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save chat IDs' }))

    await waitFor(() => expect(updateMe).toHaveBeenCalledTimes(1))
    expect(updateMe.mock.calls[0][0]).toMatchObject({ slack_username: null })
  })

  it('keeps the email of an identity-provider account read-only', () => {
    renderCard(IDP_USER)

    expect(screen.getByLabelText('Email')).toBeDisabled()
    expect(screen.getByText('Managed by your identity provider.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save email' })).not.toBeInTheDocument()
  })

  it('asks a local account to confirm the new address through the link mailed to it', async () => {
    changeEmail.mockResolvedValue({ ...LOCAL_USER, pending_email: NEW_EMAIL, email_change: 'pending_confirmation' })
    renderCard(LOCAL_USER)
    const save = screen.getByRole('button', { name: 'Save email' })

    expect(save).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: NEW_EMAIL } })
    fireEvent.click(save)

    await waitFor(() => expect(changeEmail).toHaveBeenCalledTimes(1))
    expect(changeEmail.mock.calls[0][0]).toBe(NEW_EMAIL)
    expect(await screen.findByRole('status')).toHaveTextContent(PENDING_NOTICE)
    expect(updateMe).not.toHaveBeenCalled()
  })

  it('shows the current address again once the saved change waits for its link', async () => {
    changeEmail.mockResolvedValue({ ...LOCAL_USER, pending_email: NEW_EMAIL, email_change: 'pending_confirmation' })
    const { showRefetched } = renderCard(LOCAL_USER)

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: NEW_EMAIL } })
    fireEvent.click(screen.getByRole('button', { name: 'Save email' }))
    await screen.findByRole('status')
    showRefetched({ ...LOCAL_USER, pending_email: NEW_EMAIL })

    expect(screen.getByLabelText('Email')).toHaveValue('lena@corp.com')
    expect(screen.getByRole('button', { name: 'Save email' })).toBeDisabled()
    expect(screen.getByRole('status')).toHaveTextContent(PENDING_NOTICE)
  })

  it('says the address changed and is not verified when no mail server can confirm it', async () => {
    changeEmail.mockResolvedValue({ ...LOCAL_USER, email: NEW_EMAIL, is_verified: false, email_change: 'changed' })
    renderCard(LOCAL_USER)

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: NEW_EMAIL } })
    fireEvent.click(screen.getByRole('button', { name: 'Save email' }))

    expect(await screen.findByRole('status')).toHaveTextContent(
      `Email changed to ${NEW_EMAIL}. The address is not verified.`,
    )
    expect(screen.queryByText(/open the link/i)).not.toBeInTheDocument()
  })

  it('drops the notice of an earlier pending change once the address changed at once', async () => {
    const changed = 'lena.k@corp.com'
    changeEmail.mockResolvedValue({ ...LOCAL_USER, email: changed, pending_email: null, email_change: 'changed' })
    renderCard({ ...LOCAL_USER, pending_email: NEW_EMAIL })

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: changed } })
    fireEvent.click(screen.getByRole('button', { name: 'Save email' }))

    expect(await screen.findByText(`Email changed to ${changed}. The address is not verified.`)).toBeInTheDocument()
    expect(screen.queryByText(/open the link/i)).not.toBeInTheDocument()
  })

  it('shows under the field why a new address was refused', async () => {
    changeEmail.mockRejectedValue({ response: { data: { detail: REFUSAL } } })
    renderCard(LOCAL_USER)

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: NEW_EMAIL } })
    fireEvent.click(screen.getByRole('button', { name: 'Save email' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(REFUSAL)
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'lena.other@corp.com' } })
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('shows a pending change while the current address stays in place', () => {
    renderCard({ ...LOCAL_USER, pending_email: NEW_EMAIL })

    expect(screen.getByLabelText('Email')).toHaveValue('lena@corp.com')
    expect(screen.getByRole('status')).toHaveTextContent(PENDING_NOTICE)
  })

  it('offers no pending notice when nothing is pending', () => {
    renderCard(LOCAL_USER)

    expect(screen.queryByText(/open the link/i)).not.toBeInTheDocument()
  })
})
