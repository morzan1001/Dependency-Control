import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { InviteUserDialog } from '../InviteUserDialog'

const INVITE_LINK = 'https://dc.example/accept-invite?token=t1'
const REGISTERED = 'Email already registered'
const { invite } = vi.hoisted(() => ({ invite: vi.fn() }))
const writeText = vi.fn()

vi.mock('@/api/users', () => ({ userApi: { invite } }))
vi.mock('@/hooks/queries/use-system', () => ({
  useAppConfig: () => ({ data: { notifications: { email: false } } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

beforeEach(() => {
  vi.clearAllMocks()
  invite.mockResolvedValue({ message: 'Invitation created', link: INVITE_LINK })
  // jsdom ships no Clipboard API.
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
})

function openDialog() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
      <InviteUserDialog />
    </QueryClientProvider>,
  )
  fireEvent.click(screen.getByRole('button', { name: /Invite User/ }))
}

function sendInvitation(email = 'new@test.com') {
  openDialog()
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: email } })
  fireEvent.click(screen.getByRole('button', { name: 'Send Invitation' }))
}

async function inviteAndCopyLink() {
  sendInvitation()
  const copy = await screen.findByRole('button', { name: 'Copy invitation link' })
  fireEvent.click(copy)
  return copy
}

describe('InviteUserDialog copy link', () => {
  it('shows the link in a read-only field, like the project API keys, and marks the button once the clipboard holds it', async () => {
    writeText.mockResolvedValue(undefined)

    const copy = await inviteAndCopyLink()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Invitation link copied to clipboard'))
    expect(writeText.mock.calls).toEqual([[INVITE_LINK]])
    expect(copy.querySelector('.lucide-check')).toBeInTheDocument()
    expect(screen.getByDisplayValue(INVITE_LINK)).toHaveAttribute('readonly')
    expect(screen.queryByRole('button', { name: 'Copy Link' })).not.toBeInTheDocument()
  })

  it('focuses the link with all of it selected, like the API key dialogs', async () => {
    sendInvitation()

    const link = (await screen.findByDisplayValue(INVITE_LINK)) as HTMLInputElement
    expect(link).toHaveFocus()
    expect([link.selectionStart, link.selectionEnd]).toEqual([0, INVITE_LINK.length])
  })

  it('asks for the link to be copied once no email went out, like the project API key dialogs', async () => {
    openDialog()
    expect(screen.getByRole('dialog')).toHaveAccessibleDescription(
      'Send an invitation email to a new user. They will be able to set their own password.',
    )
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@test.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Send Invitation' }))

    await screen.findByDisplayValue(INVITE_LINK)
    expect(screen.getByRole('dialog')).toHaveAccessibleDescription('Please copy the invitation link and send it to the user.')
  })

  it('tells the admin to copy the link by hand and leaves the button unmarked when the clipboard refuses', async () => {
    writeText.mockRejectedValue(new Error('denied'))

    const copy = await inviteAndCopyLink()

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Could not reach the clipboard', {
        description: 'Select the invitation link and copy it by hand',
      }),
    )
    expect(toast.success).not.toHaveBeenCalledWith(expect.stringMatching(/copied/i))
    expect(copy.querySelector('.lucide-check')).not.toBeInTheDocument()
    expect(screen.getByDisplayValue(INVITE_LINK)).toBeInTheDocument()
  })
})

describe('InviteUserDialog footer', () => {
  it('closes the form with Cancel and opens again on an empty field', () => {
    openDialog()
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@test.com' } })

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Invite User/ }))

    expect(screen.getByLabelText('Email')).toHaveValue('')
  })

  it('closes the link with the footer Close and opens again on the form', async () => {
    writeText.mockResolvedValue(undefined)
    await inviteAndCopyLink()

    fireEvent.click(screen.getByText('Close', { selector: 'button' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Invite User/ }))

    expect(screen.queryByDisplayValue(INVITE_LINK)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Send Invitation' })).toBeInTheDocument()
  })
})

describe('InviteUserDialog refusals', () => {
  it.each(['', '   '])('says under the field that the blank address %j needs an email address and sends nothing', async (blank) => {
    sendInvitation(blank)

    expect(await screen.findByRole('alert')).toHaveTextContent('Enter an email address')
    expect(screen.getByLabelText('Email')).toHaveAccessibleDescription('Enter an email address')
    expect(invite).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'lena@corp.com' } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('shows under the field why the server refused a malformed address, as the profile card does', async () => {
    const reason = 'An email address must have an @-sign.'
    const malformed = { type: 'value_error', loc: ['body', 'email'], msg: `value is not a valid email address: ${reason}` }
    invite.mockRejectedValue({ response: { status: 422, data: { detail: [malformed] } } })

    sendInvitation('lena.corp.com')

    expect((await screen.findByRole('alert')).textContent).toBe(reason)
    expect(invite.mock.calls).toEqual([['lena.corp.com']])
    expect(toast.error).not.toHaveBeenCalled()
  })

  it('shows under the field that the address is registered, without a toast', async () => {
    invite.mockRejectedValue({ response: { status: 400, data: { detail: REGISTERED } } })

    sendInvitation('lena@corp.com')

    expect(await screen.findByRole('alert')).toHaveTextContent(REGISTERED)
    expect(screen.getByLabelText('Email')).toHaveAccessibleDescription(REGISTERED)
    expect(toast.error).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'lena.k@corp.com' } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('names a failure that belongs to no field in a toast', async () => {
    invite.mockRejectedValue(new Error('Network Error'))

    sendInvitation()

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Failed to send invitation', { description: 'Network Error' }),
    )
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('opens again without the refusal shown before it was closed', async () => {
    invite.mockRejectedValue({ response: { status: 400, data: { detail: REGISTERED } } })
    sendInvitation('lena@corp.com')
    await screen.findByRole('alert')

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(screen.getByRole('button', { name: /Invite User/ }))

    expect(screen.getByLabelText('Email')).toHaveValue('')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
