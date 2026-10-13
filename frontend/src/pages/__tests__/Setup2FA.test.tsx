import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { TwoFASetup } from '@/types/user'

import Setup2FA from '../Setup2FA'

// POST /users/me/2fa/setup answers the PNG as bare base64, without a data: prefix.
const SETUP: TwoFASetup = { secret: 'JBSWY3DPEHPK3PXP', qr_code: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB' }

const { setup2FA, enable2FA } = vi.hoisted(() => ({ setup2FA: vi.fn(), enable2FA: vi.fn() }))

vi.mock('@/api/auth', () => ({ authApi: { setup2FA, enable2FA } }))
vi.mock('@/hooks/queries/use-users', () => ({ useCurrentUser: () => ({ data: { totp_enabled: false } }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const refused = (detail: string, status = 400) => ({ response: { status, data: { detail } } })

function renderPage() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
      <MemoryRouter>
        <Setup2FA />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function startSetup() {
  renderPage()
  fireEvent.click(screen.getByRole('button', { name: 'Start Setup' }))
  await screen.findByAltText('2FA QR Code')
}

async function enable(code = '123456', password = 'Correct-Horse-1') {
  await startSetup()
  fireEvent.change(screen.getByLabelText('Authenticator Code'), { target: { value: code } })
  fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: password } })
  fireEvent.click(screen.getByRole('button', { name: 'Enable 2FA' }))
}

describe('Setup2FA', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setup2FA.mockResolvedValue(SETUP)
  })

  it('sits on the card of the sign-in pages: 350px wide, the logo above a centred title and a full-width button', async () => {
    renderPage()

    const header = screen.getByRole('heading', { name: 'Setup Two-Factor Authentication' }).parentElement as HTMLElement
    expect(header).toHaveClass('text-center')
    expect(header).toContainElement(screen.getByAltText('Logo'))
    expect(header.parentElement).toHaveClass('w-[350px]')
    expect(screen.getByRole('button', { name: 'Start Setup' })).toHaveClass('w-full')
    fireEvent.click(screen.getByRole('button', { name: 'Start Setup' }))
    expect(await screen.findByRole('button', { name: 'Enable 2FA' })).toHaveClass('w-full')
  })

  it('renders the enrolment QR code from the base64 the server sends', async () => {
    await startSetup()

    expect(screen.getByAltText('2FA QR Code')).toHaveAttribute('src', `data:image/png;base64,${SETUP.qr_code}`)
  })

  it('lets the device offer the code from an authenticator, like the profile setup dialog', async () => {
    await startSetup()

    expect(screen.getByLabelText('Authenticator Code')).toHaveAttribute('autocomplete', 'one-time-code')
    expect(screen.getByLabelText('Authenticator Code')).toHaveAttribute('inputmode', 'numeric')
    expect(screen.getByLabelText('Authenticator Code')).toHaveAttribute('maxlength', '6')
  })

  it('sends the code and the current password with the Enable 2FA button of the profile setup dialog', async () => {
    enable2FA.mockResolvedValue({})

    await enable('654321', 'Correct-Horse-1')

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith('2FA enabled', { description: 'Two-factor authentication has been enabled.' }),
    )
    expect(enable2FA.mock.calls).toEqual([['654321', 'Correct-Horse-1']])
  })

  it.each([
    { field: 'Current Password', reason: 'Invalid password' },
    { field: 'Authenticator Code', reason: 'Invalid OTP code' },
  ])('shows "$reason" under the $field like the profile setup dialog and clears it once the field changes', async ({ field, reason }) => {
    enable2FA.mockRejectedValue(refused(reason))

    await enable()

    expect(await screen.findByRole('alert')).toHaveTextContent(reason)
    expect(screen.getByLabelText(field)).toHaveAccessibleDescription(reason)
    expect(toast.error).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText(field), { target: { value: '111111' } })
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('toasts a failure that belongs to no field', async () => {
    enable2FA.mockRejectedValue(refused('2FA setup not initiated'))

    await enable()

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Failed to enable 2FA', { description: '2FA setup not initiated' }),
    )
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
