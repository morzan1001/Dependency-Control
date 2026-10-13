import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { AxiosError, type InternalAxiosRequestConfig } from 'axios'
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
const SSO_USER: User = { ...LOCAL_USER, auth_provider: 'gitlab' }
const NEW_PASSWORD = 'Battery-Staple-2'
const WEAK = 'Password must contain at least one uppercase letter'
const SESSION_TOKEN = `e30.${btoa(JSON.stringify({ sub: 'u-lena', permissions: [] }))}.sig`

let sentUrls: (string | undefined)[] = []

function stubBackend() {
  sentUrls = []
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    sentUrls.push(config.url)
    return { data: LOCAL_USER, status: 200, statusText: 'OK', headers: {}, config }
  }
}

function refuseWith(status: number, detail: unknown) {
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    sentUrls.push(config.url)
    throw new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_REQUEST', config, null, {
      data: { detail }, status, statusText: 'Refused', headers: {}, config,
    })
  }
}

function fillIn(newPassword: string, confirmation = newPassword) {
  fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: 'Correct-Horse-1' } })
  fireEvent.change(screen.getByLabelText('New Password'), { target: { value: newPassword } })
  fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: confirmation } })
  fireEvent.click(screen.getByRole('button', { name: 'Update Password' }))
}

function migrate() {
  fireEvent.change(screen.getByLabelText('New Password'), { target: { value: NEW_PASSWORD } })
  fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: NEW_PASSWORD } })
  fireEvent.click(screen.getByRole('button', { name: 'Set Password & Migrate' }))
}

function renderProfile(user = LOCAL_USER) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
      <MemoryRouter initialEntries={['/profile']}>
        <AuthProvider>
          <Routes>
            <Route path="/profile" element={<PasswordUpdateCard user={user} />} />
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

    fillIn(NEW_PASSWORD)

    expect(await screen.findByText('login page')).toBeInTheDocument()
    expect(sentUrls).toContain('/users/me/password')
    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('refresh_token')).toBeNull()
    expect(toast.success).toHaveBeenCalledWith('Password updated', {
      description: 'Sign in with your new password.',
    })
  })

  it("shows the server's password policy message under the new password", async () => {
    refuseWith(422, [{ loc: ['body', 'new_password'], msg: `Value error, ${WEAK}` }])
    renderProfile()

    fillIn('battery-staple-2')

    expect(await screen.findByRole('alert')).toHaveTextContent(WEAK)
    expect(screen.getByLabelText('New Password')).toHaveAccessibleDescription(WEAK)
    expect(sentUrls).toContain('/users/me/password')
    expect(toast.error).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('New Password'), { target: { value: NEW_PASSWORD } })
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('shows a wrong current password under its field', async () => {
    refuseWith(400, 'Incorrect password')
    renderProfile()

    fillIn(NEW_PASSWORD)

    expect(await screen.findByRole('alert')).toHaveTextContent('Incorrect password')
    expect(screen.getByLabelText('Current Password')).toHaveAccessibleDescription('Incorrect password')
    expect(toast.error).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: 'Correct-Horse-2' } })
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('says under the confirmation that the new passwords differ and sends nothing', async () => {
    renderProfile()

    fillIn(NEW_PASSWORD, 'Battery-Staple-3')

    expect(await screen.findByRole('alert')).toHaveTextContent('Passwords do not match')
    expect(screen.getByLabelText('Confirm New Password')).toHaveAccessibleDescription('Passwords do not match')
    expect(sentUrls).toHaveLength(0)
    expect(toast.error).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: NEW_PASSWORD } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('toasts a failure that belongs to no field', async () => {
    refuseWith(500, 'Internal Server Error')
    renderProfile()

    fillIn(NEW_PASSWORD)

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Error', { description: 'Internal Server Error' }))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('confirms a migration to a local account', async () => {
    renderProfile(SSO_USER)

    migrate()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Account migrated', {
      description: 'Your account has been migrated to local authentication. You can now login with your password.',
    }))
    expect(sentUrls).toEqual(['/users/me/migrate'])
  })

  it('shows a migration password outside the rule under the new password', async () => {
    refuseWith(422, [{ loc: ['body', 'new_password'], msg: `Value error, ${WEAK}` }])
    renderProfile(SSO_USER)

    migrate()

    expect(await screen.findByRole('alert')).toHaveTextContent(WEAK)
    expect(screen.getByLabelText('New Password')).toHaveAccessibleDescription(WEAK)
    expect(sentUrls).toEqual(['/users/me/migrate'])
    expect(toast.error).not.toHaveBeenCalled()
  })

  it('toasts a migration the server refuses for the account rather than a field', async () => {
    refuseWith(400, 'User is already a local account.')
    renderProfile(SSO_USER)

    migrate()

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Error', { description: 'User is already a local account.' }),
    )
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
