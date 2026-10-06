import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import type { TwoFASetup } from '@/types/user'

import Setup2FA from '../Setup2FA'

// POST /users/me/2fa/setup answers the PNG as bare base64, without a data: prefix.
const SETUP: TwoFASetup = { secret: 'JBSWY3DPEHPK3PXP', qr_code: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB' }

vi.mock('@/hooks/queries/use-auth', () => ({
  useSetup2FA: () => ({
    mutate: (_: undefined, options: { onSuccess: (data: TwoFASetup) => void }) => options.onSuccess(SETUP),
    isPending: false,
  }),
  useEnable2FA: () => ({ mutate: vi.fn(), isPending: false }),
}))
vi.mock('@/hooks/queries/use-users', () => ({ useCurrentUser: () => ({ data: { totp_enabled: false } }) }))

describe('Setup2FA', () => {
  it('renders the enrolment QR code from the base64 the server sends', () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <Setup2FA />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Start Setup' }))

    expect(screen.getByAltText('2FA QR Code')).toHaveAttribute('src', `data:image/png;base64,${SETUP.qr_code}`)
  })
})
