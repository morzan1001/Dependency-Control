import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { TwoFADisableDialog } from '../TwoFADisableDialog'

const { disable2FA } = vi.hoisted(() => ({ disable2FA: vi.fn() }))

vi.mock('@/api/auth', () => ({ authApi: { disable2FA } }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const refused = (detail: string, status = 400) => ({ response: { status, data: { detail } } })

function DisableDialog() {
  const [isOpen, setIsOpen] = useState(true)
  return (
    <>
      <button type="button" onClick={() => setIsOpen(true)}>Disable</button>
      <TwoFADisableDialog isOpen={isOpen} onClose={() => setIsOpen(false)} />
    </>
  )
}

function disable(password = 'Correct-Horse-1') {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
      <DisableDialog />
    </QueryClientProvider>,
  )
  fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: password } })
  fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }))
}

describe('TwoFADisableDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('confirms that two-factor authentication is disabled', async () => {
    disable2FA.mockResolvedValue({})
    disable()

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith('2FA disabled', { description: 'Two-factor authentication has been disabled.' }),
    )
  })

  it('shows a wrong current password under its field and clears it once the field changes', async () => {
    disable2FA.mockRejectedValue(refused('Invalid password'))
    disable()

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid password')
    expect(screen.getByLabelText('Current Password')).toHaveAccessibleDescription('Invalid password')
    expect(toast.error).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: 'Correct-Horse-2' } })
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('toasts a failure that belongs to no field', async () => {
    disable2FA.mockRejectedValue(refused('2FA is not enabled for your account'))
    disable()

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Error', { description: '2FA is not enabled for your account' }),
    )
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('opens again without the refusal shown before it was closed', async () => {
    disable2FA.mockRejectedValue(refused('Invalid password'))
    disable()
    await screen.findByRole('alert')

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Disable' }))

    expect(await screen.findByLabelText('Current Password')).toHaveValue('')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
