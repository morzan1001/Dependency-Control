import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import VerifyEmail from '../VerifyEmail'

function renderPage(url: string, verifyToken: (token: string) => Promise<{ message: string }>) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
      <MemoryRouter initialEntries={[url]}>
        <VerifyEmail verifyToken={verifyToken} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('VerifyEmail', () => {
  it('confirms the token from the link and shows the answer', async () => {
    const verifyToken = vi.fn().mockResolvedValue({ message: 'Your email address has been changed' })

    renderPage('/confirm-email?token=abc.def', verifyToken)

    expect(await screen.findByRole('status')).toHaveTextContent('Your email address has been changed')
    expect(verifyToken.mock.calls[0][0]).toBe('abc.def')
  })

  it('reports a link without a token on the error card of the other link pages and calls nothing', () => {
    const verifyToken = vi.fn()

    renderPage('/confirm-email', verifyToken)

    expect(screen.getByRole('heading', { name: 'Error' })).toHaveClass('text-destructive')
    expect(screen.getByRole('alert')).toBe(screen.getByText('No verification token provided'))
    expect(screen.queryByRole('heading', { name: 'Email Verification' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to Login' })).toHaveAttribute('href', '/login')
    expect(verifyToken).not.toHaveBeenCalled()
  })

  it('reports a refused token on the error card of the other link pages', async () => {
    const verifyToken = vi.fn().mockRejectedValue({ response: { status: 400, data: { detail: 'Invalid or expired token' } } })

    renderPage('/verify-email?token=stale', verifyToken)

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid or expired token')
    expect(screen.getByRole('heading', { name: 'Error' })).toBeInTheDocument()
    expect(screen.queryByText('Verification failed.')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to Login' })).toHaveAttribute('href', '/login')
  })
})
