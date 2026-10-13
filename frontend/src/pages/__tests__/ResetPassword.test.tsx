import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { AxiosError, type InternalAxiosRequestConfig } from 'axios'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { toast } from 'sonner'
import { describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'

import ResetPassword from '../ResetPassword'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('ResetPassword', () => {
  it("shows the server's password policy message for a weak new password", async () => {
    const sentUrls: (string | undefined)[] = []
    api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
      sentUrls.push(config.url)
      const detail = [{ loc: ['body', 'new_password'], msg: 'Value error, Password must contain at least one digit' }]
      throw new AxiosError('Request failed with status code 422', 'ERR_BAD_REQUEST', config, null, {
        data: { detail }, status: 422, statusText: 'Unprocessable Entity', headers: {}, config,
      })
    }
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
        <MemoryRouter initialEntries={['/reset-password?token=t1']}>
          <ResetPassword />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    fireEvent.change(screen.getByLabelText('New Password'), { target: { value: 'Battery-Staple' } })
    fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: 'Battery-Staple' } })
    fireEvent.click(screen.getByRole('button', { name: 'Reset Password' }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Reset Failed', {
      description: 'Password must contain at least one digit',
    }))
    expect(sentUrls).toHaveLength(1)
  })

  it("sends the mailed link's token with the new password and opens the login", async () => {
    const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2JAdGVzdC5jb20ifQ.c2ln-_x'
    const sent: InternalAxiosRequestConfig[] = []
    api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
      sent.push(config)
      return { data: { message: 'Password successfully reset' }, status: 200, statusText: 'OK', headers: {}, config }
    }
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter initialEntries={[`/reset-password?token=${token}`]}>
          <Routes>
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="/login" element={<p>login page</p>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )

    fireEvent.change(screen.getByLabelText('New Password'), { target: { value: 'Battery-Staple-2' } })
    fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: 'Battery-Staple-2' } })
    fireEvent.click(screen.getByRole('button', { name: 'Reset Password' }))

    expect(await screen.findByText('login page')).toBeInTheDocument()
    expect(sent.map(({ method, url, data }) => [method, url, JSON.parse(data)])).toEqual([
      ['post', '/reset-password', { token, new_password: 'Battery-Staple-2' }],
    ])
  })
})
