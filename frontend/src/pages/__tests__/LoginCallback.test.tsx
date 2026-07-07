import { render, screen } from '@testing-library/react'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { MemoryRouter, Routes, Route } from 'react-router-dom'

import LoginCallback from '../LoginCallback'
import Login from '../Login'

// --- Mocks -----------------------------------------------------------------

const noopMutation = () => ({ mutate: vi.fn(), isPending: false })

vi.mock('@/hooks/queries/use-auth', () => ({
  useLogin: () => noopMutation(),
}))

vi.mock('@/hooks/queries/use-system', () => ({
  usePublicConfig: () => ({ data: { oidc_enabled: false } }),
}))

vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ login: vi.fn(), isAuthenticated: false }),
}))

// The callback reads globalThis.location.hash directly; capture the original so
// each test can drive a specific OIDC redirect payload.
const originalHash = globalThis.location.hash

function renderCallbackFlow() {
  return render(
    <MemoryRouter initialEntries={['/login/callback']}>
      <Routes>
        <Route path="/login/callback" element={<LoginCallback />} />
        <Route path="/login" element={<Login />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  globalThis.location.hash = originalHash
})

describe('LoginCallback failure messaging', () => {
  it('surfaces "No token provided" to the user when the hash is empty', () => {
    globalThis.location.hash = ''

    renderCallbackFlow()

    // Regression: the callback must hand Login a state key it actually renders,
    // otherwise the OIDC failure reason is silently dropped.
    expect(screen.getByText('No token provided')).toBeInTheDocument()
  })

  it('surfaces "Invalid token response" when tokens are missing from the hash', () => {
    globalThis.location.hash = '#access_token=only-one'

    renderCallbackFlow()

    expect(screen.getByText('Invalid token response')).toBeInTheDocument()
  })
})
