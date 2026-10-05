import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen } from '@testing-library/react'
import type { InternalAxiosRequestConfig } from 'axios'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import { AuthProvider } from '@/context/AuthProvider'
import type { User } from '@/types/user'

import { PasswordUpdateCard } from '../PasswordUpdateCard'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const LOCAL_USER: User = {
  id: 'u-lena',
  username: 'lena',
  email: 'lena@corp.com',
  is_active: true,
  auth_provider: 'local',
  permissions: [],
  totp_enabled: false,
}
const NEW_PASSWORD = 'Battery-Staple-2'
const SESSION_TOKEN = `e30.${btoa(JSON.stringify({ sub: 'u-lena', permissions: [] }))}.sig`

let sentUrls: (string | undefined)[] = []

function stubBackend() {
  sentUrls = []
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    sentUrls.push(config.url)
    return { data: LOCAL_USER, status: 200, statusText: 'OK', headers: {}, config }
  }
}

function renderProfile() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
      <MemoryRouter initialEntries={['/profile']}>
        <AuthProvider>
          <Routes>
            <Route path="/profile" element={<PasswordUpdateCard user={LOCAL_USER} />} />
            <Route path="/login" element={<div>login page</div>} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('PasswordUpdateCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    stubBackend()
  })

  it('signs out after a password change, which the server already ended the session for', async () => {
    localStorage.setItem('token', SESSION_TOKEN)
    localStorage.setItem('refresh_token', 'refresh-token')
    renderProfile()

    fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: 'Correct-Horse-1' } })
    fireEvent.change(screen.getByLabelText('New Password'), { target: { value: NEW_PASSWORD } })
    fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: NEW_PASSWORD } })
    fireEvent.click(screen.getByRole('button', { name: 'Update Password' }))

    expect(await screen.findByText('login page')).toBeInTheDocument()
    expect(sentUrls).toContain('/users/me/password')
    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('refresh_token')).toBeNull()
    expect(toast.success).toHaveBeenCalledWith('Password updated', {
      description: 'Sign in with your new password.',
    })
  })
})
