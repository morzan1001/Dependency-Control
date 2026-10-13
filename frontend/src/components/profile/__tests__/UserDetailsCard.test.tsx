import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { useCurrentUser, userKeys } from '@/hooks/queries/use-users'
import type { User } from '@/types/user'

import { UserDetailsCard } from '../UserDetailsCard'

const { updateMe, changeEmail, getMe } = vi.hoisted(() => ({
  updateMe: vi.fn(),
  changeEmail: vi.fn(),
  getMe: vi.fn(),
}))

vi.mock('@/api/users', () => ({ userApi: { updateMe, changeEmail, getMe } }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const NEW_EMAIL = 'lena.new@corp.com'
const PENDING_NOTICE = `Open the link sent to ${NEW_EMAIL} to confirm the change. Until then, lena@corp.com stays your address.`
const REFUSAL = 'Email verification is required, but no mail server is configured to confirm a new address'
const TAKEN = 'Username already taken'
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
const PENDING_RESULT = { ...LOCAL_USER, pending_email: NEW_EMAIL, email_change: 'pending_confirmation' }

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

function SignedInCard() {
  const { data } = useCurrentUser()
  return <UserDetailsCard user={data} notificationChannels={['slack']} />
}

const type = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } })
const saveButton = () => screen.getByRole('button', { name: 'Save Changes' })
const save = () => fireEvent.click(saveButton())
const refused = (detail: string) => ({ response: { data: { detail } } })

describe('UserDetailsCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it.each([[['email']], [['email', 'mattermost']], [['slack', 'mattermost']]])(
    'offers one Save Changes button with channels %j',
    (channels) => {
      renderCard(LOCAL_USER, channels)

      expect(screen.getAllByRole('button').map((button) => button.textContent)).toEqual(['Save Changes'])
      expect(saveButton()).toBeEnabled()
    },
  )

  it('confirms a save with nothing changed without sending anything', async () => {
    renderCard(LOCAL_USER)

    type('Username', ' lena ')
    save()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Profile updated'))
    expect(toast.success).toHaveBeenCalledTimes(1)
    expect(updateMe).not.toHaveBeenCalled()
    expect(changeEmail).not.toHaveBeenCalled()
  })

  it('saves only the chat ID that changed', async () => {
    updateMe.mockResolvedValue({ ...LOCAL_USER, slack_username: 'U123', mattermost_username: 'lena-mm' })
    renderCard({ ...LOCAL_USER, mattermost_username: 'lena-mm' }, ['slack', 'mattermost'])

    type('Slack Member ID', 'U123')
    save()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Profile updated'))
    expect(updateMe.mock.calls).toEqual([[{ slack_username: 'U123' }]])
    expect(changeEmail).not.toHaveBeenCalled()
  })

  it('saves the chat IDs of an account whose stored address the browser would refuse', async () => {
    const jorg = { ...LOCAL_USER, email: 'jörg@corp.com' }
    updateMe.mockResolvedValue({ ...jorg, slack_username: 'U1' })
    renderCard(jorg)

    type('Slack Member ID', 'U1')
    save()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Profile updated'))
    expect(updateMe.mock.calls).toEqual([[{ slack_username: 'U1' }]])
    expect(changeEmail).not.toHaveBeenCalled()
  })

  it('saves the Mattermost username where it is the only chat field', async () => {
    updateMe.mockResolvedValue({ ...LOCAL_USER, mattermost_username: 'lena-mm' })
    renderCard(LOCAL_USER, ['email', 'mattermost'])

    type('Mattermost Username', 'lena-mm')
    save()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Profile updated'))
    expect(updateMe.mock.calls).toEqual([[{ mattermost_username: 'lena-mm' }]])
  })

  it('removes a stored Slack member ID when the field is emptied', async () => {
    updateMe.mockResolvedValue(LOCAL_USER)
    renderCard({ ...LOCAL_USER, slack_username: 'U123' })

    type('Slack Member ID', '')
    save()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Profile updated'))
    expect(updateMe.mock.calls).toEqual([[{ slack_username: null }]])
  })

  it('renames a local account and tells it to sign in with the new name', async () => {
    updateMe.mockResolvedValue({ ...LOCAL_USER, username: 'lena.k' })
    renderCard(LOCAL_USER)

    type('Username', ' lena.k ')
    save()

    expect(await screen.findByRole('status')).toHaveTextContent('You now sign in as lena.k.')
    expect(updateMe.mock.calls).toEqual([[{ username: 'lena.k' }]])
    expect(screen.getByLabelText('Username')).toHaveValue('lena.k')
    expect(toast.success).toHaveBeenCalledTimes(1)
    expect(toast.success).toHaveBeenCalledWith('Profile updated')
  })

  it('confirms the rename of an identity-provider account without a sign-in note', async () => {
    updateMe.mockResolvedValue({ ...IDP_USER, username: 'otto.k' })
    renderCard(IDP_USER)

    type('Username', 'otto.k')
    save()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Profile updated'))
    expect(updateMe.mock.calls).toEqual([[{ username: 'otto.k' }]])
    expect(screen.queryByText(/sign in as/i)).not.toBeInTheDocument()
  })

  it('saves a new name and new chat IDs in one request', async () => {
    updateMe.mockResolvedValue({ ...LOCAL_USER, username: 'lena.k', slack_username: 'U123' })
    renderCard(LOCAL_USER)

    type('Username', 'lena.k')
    type('Slack Member ID', 'U123')
    save()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Profile updated'))
    expect(updateMe.mock.calls).toEqual([[{ username: 'lena.k', slack_username: 'U123' }]])
  })

  it('shows under the field why a new name was refused and keeps what was typed', async () => {
    updateMe.mockRejectedValue(refused(TAKEN))
    renderCard(LOCAL_USER)

    type('Username', 'otto')
    type('Slack Member ID', 'U123')
    save()

    expect(await screen.findByRole('alert')).toHaveTextContent(TAKEN)
    expect(screen.getByLabelText('Username')).toHaveAccessibleDescription(TAKEN)
    expect(screen.getByLabelText('Username')).toHaveValue('otto')
    expect(screen.getByLabelText('Slack Member ID')).toHaveValue('U123')
    expect(toast.success).not.toHaveBeenCalled()
    expect(toast.error).not.toHaveBeenCalled()
    type('Username', 'otto2')
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('reports a failed chat ID save', async () => {
    updateMe.mockRejectedValue(new Error('Network Error'))
    renderCard(LOCAL_USER)

    type('Slack Member ID', 'U123')
    save()

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Error', { description: 'Network Error' }))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(toast.success).not.toHaveBeenCalled()
  })

  it.each([
    { field: 'Username', value: 'lena.k', refetched: { ...LOCAL_USER, username: 'lena.k' } },
    { field: 'Email', value: NEW_EMAIL, refetched: { ...LOCAL_USER, pending_email: NEW_EMAIL } },
  ])('stays busy saving the $field until the refetched account arrives', async ({ field, value, refetched }) => {
    updateMe.mockResolvedValue({ ...LOCAL_USER, username: 'lena.k' })
    changeEmail.mockResolvedValue(PENDING_RESULT)
    let answerRefetch: (user: User) => void = () => undefined
    getMe.mockReturnValue(new Promise((resolve) => (answerRefetch = resolve)))
    const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
    client.setQueryData(userKeys.me, LOCAL_USER)
    render(
      <QueryClientProvider client={client}>
        <SignedInCard />
      </QueryClientProvider>,
    )

    type(field, value)
    save()
    await act(() => new Promise((resolve) => setTimeout(resolve, 0)))

    expect(getMe).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: 'Saving...' })).toBeDisabled()

    answerRefetch(refetched)
    expect(await screen.findByRole('button', { name: 'Save Changes' })).toBeInTheDocument()
  })

  it.each([
    { field: 'Username', sent: 'lena.k', typed: 'lena.kx' },
    { field: 'Email', sent: NEW_EMAIL, typed: 'lena.x@corp.com' },
  ])('stays busy saving the $field and keeps what is typed meanwhile', async ({ field, sent, typed }) => {
    let finish: () => void = () => undefined
    const finished = new Promise<void>((resolve) => (finish = resolve))
    updateMe.mockImplementation(() => finished.then(() => ({ ...LOCAL_USER, username: 'lena.k' })))
    changeEmail.mockImplementation(() => finished.then(() => PENDING_RESULT))
    renderCard(LOCAL_USER)

    type(field, sent)
    save()
    await screen.findByRole('button', { name: 'Saving...' })
    type(field, typed)
    await act(() => new Promise((resolve) => setTimeout(resolve, 0)))

    expect(screen.getByRole('button', { name: 'Saving...' })).toBeDisabled()
    finish()
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Profile updated'))
    expect(screen.getByLabelText(field)).toHaveValue(typed)
  })

  it('lets the fields nobody edited follow the refetched account', async () => {
    const refetched = {
      ...LOCAL_USER,
      username: 'lena.k',
      email: 'lena.k@corp.com',
      slack_username: 'U9',
      mattermost_username: 'lena-mm',
    }
    updateMe.mockResolvedValue({ ...refetched, slack_username: 'U1' })
    const { showRefetched } = renderCard(LOCAL_USER, ['slack', 'mattermost'])

    showRefetched(refetched)
    expect(screen.getByLabelText('Username')).toHaveValue('lena.k')
    expect(screen.getByLabelText('Email')).toHaveValue('lena.k@corp.com')
    expect(screen.getByLabelText('Slack Member ID')).toHaveValue('U9')
    expect(screen.getByLabelText('Mattermost Username')).toHaveValue('lena-mm')
    type('Slack Member ID', 'U1')
    save()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Profile updated'))
    expect(updateMe.mock.calls).toEqual([[{ slack_username: 'U1' }]])
    expect(changeEmail).not.toHaveBeenCalled()
  })

  it('keeps what was typed when the account is refetched', () => {
    const { showRefetched } = renderCard(LOCAL_USER, ['slack', 'mattermost'])
    type('Username', 'lena.x')
    type('Email', 'lena.x@corp.com')
    type('Slack Member ID', 'U1')
    type('Mattermost Username', 'lena-x')

    showRefetched({
      ...LOCAL_USER,
      username: 'lena.k',
      email: 'lena.k@corp.com',
      slack_username: 'U9',
      mattermost_username: 'lena-mm',
    })

    expect(screen.getByLabelText('Username')).toHaveValue('lena.x')
    expect(screen.getByLabelText('Email')).toHaveValue('lena.x@corp.com')
    expect(screen.getByLabelText('Slack Member ID')).toHaveValue('U1')
    expect(screen.getByLabelText('Mattermost Username')).toHaveValue('lena-x')
  })

  it.each(['', '   '])('offers no save for the blank name %j', async (blank) => {
    renderCard(LOCAL_USER)

    type('Username', blank)
    expect(saveButton()).toBeDisabled()
    save()
    await act(() => new Promise((resolve) => setTimeout(resolve, 0)))

    expect(updateMe).not.toHaveBeenCalled()
  })

  it('keeps the email of an identity-provider account read-only', () => {
    renderCard(IDP_USER)

    expect(screen.getByLabelText('Email')).toBeDisabled()
    expect(screen.getByLabelText('Email')).toHaveValue('otto@corp.com')
    expect(screen.getByText('Managed by your identity provider.')).toBeInTheDocument()
  })

  it('asks a local account to confirm the new address through the link mailed to it', async () => {
    changeEmail.mockResolvedValue(PENDING_RESULT)
    renderCard(LOCAL_USER)

    type('Email', NEW_EMAIL)
    save()

    expect(await screen.findByRole('status')).toHaveTextContent(PENDING_NOTICE)
    expect(changeEmail.mock.calls).toEqual([[NEW_EMAIL]])
    expect(updateMe).not.toHaveBeenCalled()
    expect(toast.success).toHaveBeenCalledTimes(1)
    expect(toast.success).toHaveBeenCalledWith('Profile updated')
  })

  it('shows the current address again once the saved change waits for its link', async () => {
    changeEmail.mockResolvedValue(PENDING_RESULT)
    const { showRefetched } = renderCard(LOCAL_USER)

    type('Email', NEW_EMAIL)
    save()
    await screen.findByRole('status')
    showRefetched({ ...LOCAL_USER, pending_email: NEW_EMAIL })

    expect(screen.getByLabelText('Email')).toHaveValue('lena@corp.com')
    expect(screen.getByRole('status')).toHaveTextContent(PENDING_NOTICE)
    save()
    await waitFor(() => expect(toast.success).toHaveBeenCalledTimes(2))
    expect(changeEmail).toHaveBeenCalledTimes(1)
  })

  it('says the address changed and is not verified when no mail server can confirm it', async () => {
    changeEmail.mockResolvedValue({ ...LOCAL_USER, email: NEW_EMAIL, is_verified: false, email_change: 'changed' })
    renderCard(LOCAL_USER)

    type('Email', NEW_EMAIL)
    save()

    expect(await screen.findByRole('status')).toHaveTextContent(
      `Email changed to ${NEW_EMAIL}. The address is not verified.`,
    )
    expect(screen.getByLabelText('Email')).toHaveValue(NEW_EMAIL)
    expect(screen.queryByText(/open the link/i)).not.toBeInTheDocument()
  })

  it('drops the notice of an earlier pending change once the address changed at once', async () => {
    const changed = 'lena.k@corp.com'
    changeEmail.mockResolvedValue({ ...LOCAL_USER, email: changed, pending_email: null, email_change: 'changed' })
    renderCard({ ...LOCAL_USER, pending_email: NEW_EMAIL })

    type('Email', changed)
    save()

    expect(await screen.findByText(`Email changed to ${changed}. The address is not verified.`)).toBeInTheDocument()
    expect(screen.queryByText(/open the link/i)).not.toBeInTheDocument()
  })

  it('shows under the field why a new address was refused', async () => {
    changeEmail.mockRejectedValue(refused(REFUSAL))
    renderCard(LOCAL_USER)

    type('Email', NEW_EMAIL)
    save()

    expect(await screen.findByRole('alert')).toHaveTextContent(REFUSAL)
    expect(screen.getByLabelText('Email')).toHaveAccessibleDescription(REFUSAL)
    expect(toast.success).not.toHaveBeenCalled()
    type('Email', 'lena.other@corp.com')
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('saves a new name and a new address with one click', async () => {
    updateMe.mockResolvedValue({ ...LOCAL_USER, username: 'lena.k' })
    changeEmail.mockResolvedValue({ ...PENDING_RESULT, username: 'lena.k' })
    renderCard(LOCAL_USER)

    type('Username', 'lena.k')
    type('Email', NEW_EMAIL)
    save()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Profile updated'))
    expect(toast.success).toHaveBeenCalledTimes(1)
    expect(updateMe.mock.calls).toEqual([[{ username: 'lena.k' }]])
    expect(changeEmail.mock.calls).toEqual([[NEW_EMAIL]])
    expect(screen.getAllByRole('status').map((note) => note.textContent)).toEqual([
      'You now sign in as lena.k.',
      PENDING_NOTICE,
    ])
  })

  it('keeps a saved address waiting for its link when the new name is refused', async () => {
    updateMe.mockRejectedValue(refused(TAKEN))
    changeEmail.mockResolvedValue(PENDING_RESULT)
    renderCard(LOCAL_USER)

    type('Username', 'otto')
    type('Email', NEW_EMAIL)
    save()

    expect(await screen.findByRole('status')).toHaveTextContent(PENDING_NOTICE)
    expect(await screen.findByRole('alert')).toHaveTextContent(TAKEN)
    expect(screen.getByLabelText('Username')).toHaveAccessibleDescription(TAKEN)
    expect(screen.getByLabelText('Username')).toHaveValue('otto')
    expect(screen.getByLabelText('Email')).toHaveValue('lena@corp.com')
    expect(toast.success).toHaveBeenCalledTimes(1)
    expect(toast.success).toHaveBeenCalledWith('Profile updated')
  })

  it('keeps a saved name when the new address is refused', async () => {
    updateMe.mockResolvedValue({ ...LOCAL_USER, username: 'lena.k' })
    changeEmail.mockRejectedValue(refused(REFUSAL))
    renderCard(LOCAL_USER)

    type('Username', 'lena.k')
    type('Email', NEW_EMAIL)
    save()

    expect(await screen.findByRole('alert')).toHaveTextContent(REFUSAL)
    expect(screen.getByLabelText('Email')).toHaveAccessibleDescription(REFUSAL)
    expect(await screen.findByRole('status')).toHaveTextContent('You now sign in as lena.k.')
    expect(screen.getByLabelText('Email')).toHaveValue(NEW_EMAIL)
    expect(toast.success).toHaveBeenCalledTimes(1)
    expect(toast.success).toHaveBeenCalledWith('Profile updated')
  })

  it('confirms a saved chat ID when the new address is refused', async () => {
    updateMe.mockResolvedValue({ ...LOCAL_USER, slack_username: 'U123' })
    changeEmail.mockRejectedValue(refused(REFUSAL))
    renderCard(LOCAL_USER)

    type('Slack Member ID', 'U123')
    type('Email', NEW_EMAIL)
    save()

    expect(await screen.findByRole('alert')).toHaveTextContent(REFUSAL)
    expect(updateMe.mock.calls).toEqual([[{ slack_username: 'U123' }]])
    expect(toast.success).toHaveBeenCalledTimes(1)
    expect(toast.success).toHaveBeenCalledWith('Profile updated')
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
