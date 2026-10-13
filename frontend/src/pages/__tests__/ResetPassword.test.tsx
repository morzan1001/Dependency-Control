import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen } from '@testing-library/react'
import { AxiosError, type InternalAxiosRequestConfig } from 'axios'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'

import ResetPassword from '../ResetPassword'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const sent: InternalAxiosRequestConfig[] = []

function answer(status: number, data: unknown) {
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    sent.push(config)
    if (status < 400) return { data, status, statusText: 'OK', headers: {}, config }
    throw new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_REQUEST', config, null, {
      data, status, statusText: 'Refused', headers: {}, config,
    })
  }
}

function renderResetPage(path = '/reset-password?token=t1') {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/login" element={<p>login page</p>} />
          <Route path="/forgot-password" element={<p>forgot password page</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function submit(password: string, confirmation = password) {
  fireEvent.change(screen.getByLabelText('New Password'), { target: { value: password } })
  fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: confirmation } })
  fireEvent.click(screen.getByRole('button', { name: 'Reset Password' }))
}

describe('ResetPassword', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sent.length = 0
  })

  it("shows the server's password policy message for a weak new password in the card", async () => {
    answer(422, { detail: [{ loc: ['body', 'new_password'], msg: 'Value error, Password must contain at least one digit' }] })
    renderResetPage()

    submit('Battery-Staple')

    expect(await screen.findByRole('alert')).toHaveTextContent('Password must contain at least one digit')
    expect(screen.queryByRole('link', { name: 'Request a new link' })).not.toBeInTheDocument()
    expect(toast.error).not.toHaveBeenCalled()
    expect(sent).toHaveLength(1)
  })

  it('says in the card that the passwords differ and sends nothing', async () => {
    answer(200, { message: 'Password successfully reset' })
    renderResetPage()

    submit('Battery-Staple-2', 'Battery-Staple-3')

    expect(await screen.findByRole('alert')).toHaveTextContent('Passwords do not match')
    expect(sent).toHaveLength(0)
  })

  it('offers a new link when the server refuses the token as invalid or expired', async () => {
    answer(400, { detail: 'Invalid or expired reset token' })
    renderResetPage()

    submit('Battery-Staple-2')

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid or expired reset token')
    fireEvent.click(screen.getByRole('link', { name: 'Request a new link' }))
    expect(await screen.findByText('forgot password page')).toBeInTheDocument()
  })

  it('shows the error card of the other link pages for a link that carries no token, with a new link on offer', async () => {
    renderResetPage('/reset-password')

    expect(screen.getByRole('heading', { name: 'Error' })).toBeInTheDocument()
    expect(screen.getByText('The password reset link is invalid or missing a token.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to Login' })).toHaveAttribute('href', '/login')
    expect(screen.queryByRole('button', { name: 'Reset Password' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('link', { name: 'Request a new link' }))
    expect(await screen.findByText('forgot password page')).toBeInTheDocument()
  })

  it("sends the mailed link's token with the new password and opens the login", async () => {
    const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2JAdGVzdC5jb20ifQ.c2ln-_x'
    answer(200, { message: 'Password successfully reset' })
    renderResetPage(`/reset-password?token=${token}`)

    submit('Battery-Staple-2')

    expect(await screen.findByText('login page')).toBeInTheDocument()
    expect(sent.map(({ method, url, data }) => [method, url, JSON.parse(data)])).toEqual([
      ['post', '/reset-password', { token, new_password: 'Battery-Staple-2' }],
    ])
    expect(toast.success).toHaveBeenCalledWith('Password Reset Successful', {
      description: 'You can now login with your new password.',
    })
  })

  it('keeps the fields open while the reset is sent, like the other auth forms', async () => {
    api.defaults.adapter = () => new Promise(() => undefined)
    renderResetPage()

    submit('Battery-Staple-2')

    expect(await screen.findByRole('button', { name: 'Resetting...' })).toBeDisabled()
    expect(screen.getByLabelText('New Password')).toBeEnabled()
    expect(screen.getByLabelText('Confirm New Password')).toBeEnabled()
  })

  it('lets a password manager offer a new password for both fields', () => {
    renderResetPage()

    expect(screen.getByLabelText('New Password')).toHaveAttribute('autocomplete', 'new-password')
    expect(screen.getByLabelText('Confirm New Password')).toHaveAttribute('autocomplete', 'new-password')
  })
})
