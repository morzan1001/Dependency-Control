import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { createMutationCache } from '@/lib/mutation-cache'
import type { User } from '@/types/user'

import { TwoFactorAuthCard } from '../TwoFactorAuthCard'

const { setup2FA } = vi.hoisted(() => ({ setup2FA: vi.fn() }))

vi.mock('@/api/auth', () => ({ authApi: { setup2FA } }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const USER: User = { id: 'u1', username: 'u1', email: 'u1@test.com', is_active: true, permissions: [], totp_enabled: false }

function enable2FA() {
  render(
    <QueryClientProvider client={new QueryClient({ mutationCache: createMutationCache() })}>
      <TwoFactorAuthCard user={USER} />
    </QueryClientProvider>,
  )
  fireEvent.click(screen.getByRole('button', { name: 'Enable 2FA' }))
}

describe('TwoFactorAuthCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('opens the setup dialog with the secret the server issued', async () => {
    setup2FA.mockResolvedValue({ secret: 'ABC', qr_code: '' })

    enable2FA()

    expect(await screen.findByText('ABC', { selector: 'code' })).toBeInTheDocument()
  })

  it('titles a failed setup like the 2FA setup page and names the reason', async () => {
    setup2FA.mockRejectedValue({ response: { status: 400, data: { detail: '2FA is already enabled' } } })

    enable2FA()

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to start 2FA setup', { description: '2FA is already enabled' }))
  })
})
