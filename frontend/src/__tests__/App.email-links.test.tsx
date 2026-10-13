import { fireEvent, render, screen } from '@testing-library/react'
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const getPublicConfig = vi.hoisted(() => vi.fn())
vi.mock('@/api/system', () => ({ systemApi: { getPublicConfig } }))

const NEUTRAL_ANSWER = 'If an account with this email exists, a password reset email has been sent.'
const MAIL = { allow_public_registration: false, oidc_enabled: false, password_reset_enabled: true }
const NO_MAIL = { ...MAIL, password_reset_enabled: false }

const sent: InternalAxiosRequestConfig[] = []
let answer: (config: InternalAxiosRequestConfig) => AxiosResponse

// App holds its QueryClient at module level, so each test loads a fresh copy.
async function renderAppAt(path: string) {
  vi.resetModules()
  globalThis.history.replaceState(null, '', path)
  const { api } = await import('@/api/client')
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    sent.push(config)
    return answer(config)
  }
  const { default: App } = await import('../App')
  render(<App />)
}

function requestLinkFor(email: string, submitLabel: string) {
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: email } })
  fireEvent.click(screen.getByRole('button', { name: submitLabel }))
}

function requestsSent() {
  return sent.map(({ method, url, data }) => [method, url, JSON.parse(data)])
}

beforeEach(() => {
  vi.clearAllMocks()
  sent.length = 0
  answer = (config) => ({ data: { message: NEUTRAL_ANSWER }, status: 200, statusText: 'OK', headers: {}, config })
  localStorage.clear()
  sessionStorage.clear()
  globalThis.matchMedia = vi.fn().mockReturnValue({ matches: false, addListener: vi.fn(), removeListener: vi.fn() })
})

describe('forgot password', () => {
  it('leads from the login form to a reset request that answers the same for every address', async () => {
    getPublicConfig.mockResolvedValue(MAIL)
    await renderAppAt('/login')

    fireEvent.click(await screen.findByRole('link', { name: 'Forgot password?' }))
    expect(await screen.findByRole('heading', { name: 'Forgot Password' })).toBeInTheDocument()
    requestLinkFor('bob@test.com', 'Send Reset Email')

    expect(await screen.findByRole('status')).toHaveTextContent(NEUTRAL_ANSWER)
    expect(requestsSent()).toEqual([['post', '/forgot-password', { email: 'bob@test.com' }]])
  })

  it('is not offered while the server has no mail server to send the link', async () => {
    getPublicConfig.mockResolvedValue(NO_MAIL)
    await renderAppAt('/login')

    expect(await screen.findByRole('button', { name: 'Login' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Forgot password?' })).not.toBeInTheDocument()
  })

  it('says why a request opened without a mail server cannot be sent', async () => {
    getPublicConfig.mockResolvedValue(NO_MAIL)
    answer = (config) => {
      throw new AxiosError('Request failed with status code 501', 'ERR_BAD_RESPONSE', config, null, {
        data: { detail: 'Email server not configured' }, status: 501, statusText: 'Not Implemented', headers: {}, config,
      })
    }
    await renderAppAt('/forgot-password')

    requestLinkFor('bob@test.com', 'Send Reset Email')

    expect(await screen.findByRole('alert')).toHaveTextContent('Email server not configured')
  })

  it('tells single sign-on users that their identity provider resets their password', async () => {
    getPublicConfig.mockResolvedValue({ ...MAIL, oidc_enabled: true })
    await renderAppAt('/forgot-password')

    expect(await screen.findByText(/single sign-on accounts reset their password with their identity provider/i))
      .toBeInTheDocument()
  })
})

describe('resend verification', () => {
  it('requests a new verification link for the address typed', async () => {
    const verificationAnswer = 'If an account with this email exists, a verification email has been sent.'
    answer = (config) => ({ data: { message: verificationAnswer }, status: 200, statusText: 'OK', headers: {}, config })
    getPublicConfig.mockResolvedValue(MAIL)
    await renderAppAt('/resend-verification')

    requestLinkFor('bob@test.com', 'Send Verification Email')

    expect(await screen.findByText(verificationAnswer)).toBeInTheDocument()
    expect(requestsSent()).toEqual([['post', '/resend-verification', { email: 'bob@test.com' }]])
  })
})
