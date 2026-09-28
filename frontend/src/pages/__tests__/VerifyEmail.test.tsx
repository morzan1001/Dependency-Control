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

    expect(await screen.findByText('Your email address has been changed')).toBeInTheDocument()
    expect(verifyToken.mock.calls[0][0]).toBe('abc.def')
  })

  it('reports a link without a token and calls nothing', () => {
    const verifyToken = vi.fn()

    renderPage('/confirm-email', verifyToken)

    expect(screen.getByText('No verification token provided.')).toBeInTheDocument()
    expect(verifyToken).not.toHaveBeenCalled()
  })
})
