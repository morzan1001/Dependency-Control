import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { userApi } from '@/api/users'
import { createMutationCache } from '@/lib/mutation-cache'
import type { User } from '@/types/user'

import { NotificationPreferencesCard } from '../NotificationPreferencesCard'

vi.mock('@/api/users', () => ({ userApi: { updateMe: vi.fn() } }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const USER: User = {
  id: 'u1',
  username: 'u1',
  email: 'u1@test.com',
  is_active: true,
  permissions: [],
  totp_enabled: false,
  notification_preferences: { analysis_completed: ['email'] },
}

function renderCard(availableChannels: string[] | undefined = ['email']) {
  return render(
    <QueryClientProvider client={new QueryClient({ mutationCache: createMutationCache() })}>
      <NotificationPreferencesCard user={USER} availableChannels={availableChannels} />
    </QueryClientProvider>,
  )
}

describe('NotificationPreferencesCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows nothing while no channel is configured', () => {
    const { container } = renderCard([])

    expect(container).toBeEmptyDOMElement()
  })

  it('saves the events that keep a channel and leaves the unchecked ones out', async () => {
    vi.mocked(userApi.updateMe).mockResolvedValue(USER)
    renderCard()

    fireEvent.click(screen.getByRole('checkbox', { name: 'Analysis Completed: Email' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Vulnerability Found: Email' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Preferences' }))

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Notification preferences saved'))
    expect(userApi.updateMe).toHaveBeenCalledWith({ notification_preferences: { vulnerability_found: ['email'] } })
  })

  it('names a save that failed and why', async () => {
    vi.mocked(userApi.updateMe).mockRejectedValue(new Error('Network Error'))
    renderCard()

    fireEvent.click(screen.getByRole('button', { name: 'Save Preferences' }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to save preferences', { description: 'Network Error' }))
  })
})
