import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { InviteUserDialog } from '../InviteUserDialog'

const INVITE_LINK = 'https://dc.example/accept-invite?token=t1'
const writeText = vi.fn()

vi.mock('@/hooks/queries/use-users', () => ({
  useInviteUser: () => ({
    mutate: (_email: string, opts: { onSuccess: (data: { link: string }) => void }) => opts.onSuccess({ link: INVITE_LINK }),
    isPending: false,
  }),
}))
vi.mock('@/hooks/queries/use-system', () => ({
  useAppConfig: () => ({ data: { notifications: { email: false } } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

beforeEach(() => {
  vi.clearAllMocks()
  // jsdom ships no Clipboard API.
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
})

function inviteAndCopyLink() {
  render(<InviteUserDialog />)
  fireEvent.click(screen.getByRole('button', { name: /Invite User/ }))
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@test.com' } })
  fireEvent.click(screen.getByRole('button', { name: 'Send Invitation' }))
  fireEvent.click(screen.getByRole('button', { name: 'Copy Link' }))
}

describe('InviteUserDialog copy link', () => {
  it('confirms the copy once the clipboard holds the link', async () => {
    writeText.mockResolvedValue(undefined)

    inviteAndCopyLink()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Invitation link copied to clipboard'))
    expect(writeText.mock.calls).toEqual([[INVITE_LINK]])
  })

  it('tells the admin to copy the link by hand when the clipboard refuses', async () => {
    writeText.mockRejectedValue(new Error('denied'))

    inviteAndCopyLink()

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Could not reach the clipboard', {
        description: expect.stringMatching(/copy it by hand/i),
      }),
    )
    expect(toast.success).not.toHaveBeenCalledWith(expect.stringMatching(/copied/i))
    expect(screen.getByText(INVITE_LINK)).toBeInTheDocument()
  })
})

describe('InviteUserDialog footer', () => {
  it('closes the form with Cancel and opens again on an empty field', () => {
    render(<InviteUserDialog />)
    fireEvent.click(screen.getByRole('button', { name: /Invite User/ }))
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@test.com' } })

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Invite User/ }))

    expect(screen.getByLabelText('Email')).toHaveValue('')
  })

  it('closes the link with Close beside Copy Link and opens again on the form', () => {
    writeText.mockResolvedValue(undefined)
    inviteAndCopyLink()

    fireEvent.click(screen.getByText('Close', { selector: 'button' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Invite User/ }))

    expect(screen.queryByText(INVITE_LINK)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Send Invitation' })).toBeInTheDocument()
  })
})
