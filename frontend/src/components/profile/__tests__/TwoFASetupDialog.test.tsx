import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { TwoFASetupDialog } from '../TwoFASetupDialog'

const { enable2FA } = vi.hoisted(() => ({ enable2FA: vi.fn() }))

vi.mock('@/api/auth', () => ({ authApi: { enable2FA } }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const refused = (detail: string, status = 400) => ({ response: { status, data: { detail } } })

function SetupDialog() {
  const [isOpen, setIsOpen] = useState(true)
  return (
    <>
      <button type="button" onClick={() => setIsOpen(true)}>Set up 2FA</button>
      <TwoFASetupDialog setupData={{ secret: 'ABC', qr_code: '' }} isOpen={isOpen} onClose={() => setIsOpen(false)} />
    </>
  )
}

function enable(code = '123456', password = 'Correct-Horse-1') {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
      <SetupDialog />
    </QueryClientProvider>,
  )
  fireEvent.change(screen.getByLabelText('Authenticator Code'), { target: { value: code } })
  fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: password } })
  fireEvent.click(screen.getByRole('button', { name: 'Enable 2FA' }))
}

describe('TwoFASetupDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows the QR code and the secret like the forced setup page', () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <SetupDialog />
      </QueryClientProvider>,
    )

    expect(screen.getByAltText('2FA QR Code')).toBeInTheDocument()
    expect(screen.getByText('ABC', { selector: 'code' })).toHaveClass('bg-muted')
  })

  it('confirms that two-factor authentication is enabled', async () => {
    enable2FA.mockResolvedValue({})
    enable()

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith('2FA enabled', { description: 'Two-factor authentication has been enabled.' }),
    )
  })

  it.each([
    { field: 'Current Password', reason: 'Invalid password' },
    { field: 'Authenticator Code', reason: 'Invalid OTP code' },
  ])('shows "$reason" under the $field and clears it once the field changes', async ({ field, reason }) => {
    enable2FA.mockRejectedValue(refused(reason))
    enable()

    expect(await screen.findByRole('alert')).toHaveTextContent(reason)
    expect(screen.getByLabelText(field)).toHaveAccessibleDescription(reason)
    expect(toast.error).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText(field), { target: { value: '654321' } })
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('toasts a failure that belongs to no field', async () => {
    enable2FA.mockRejectedValue(refused('2FA setup not initiated'))
    enable()

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Error', { description: '2FA setup not initiated' }))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('opens again without the refusal shown before it was closed', async () => {
    enable2FA.mockRejectedValue(refused('Invalid password'))
    enable()
    await screen.findByRole('alert')

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Set up 2FA' }))

    expect(await screen.findByLabelText('Current Password')).toHaveValue('')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
