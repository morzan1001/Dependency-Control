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

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith(expect.stringMatching(/copied/i)))
    expect(writeText.mock.calls).toEqual([[INVITE_LINK]])
  })

  it('tells the admin to copy the link by hand when the clipboard refuses', async () => {
    writeText.mockRejectedValue(new Error('denied'))

    inviteAndCopyLink()

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith(expect.stringMatching(/copy it by hand/i)))
    expect(toast.success).not.toHaveBeenCalledWith(expect.stringMatching(/copied/i))
    expect(screen.getByText(INVITE_LINK)).toBeInTheDocument()
  })
})
