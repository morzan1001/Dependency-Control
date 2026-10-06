import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import DashboardLayout from '../DashboardLayout'

vi.mock('@/context', () => ({ useAuth: () => ({ logout: vi.fn(), hasPermission: () => false }) }))
vi.mock('@/hooks/queries/use-system', () => ({ useAppConfig: () => ({ data: undefined }) }))

const CRASH_MESSAGE = 'page exploded'

function CrashingPage(): never {
  throw new Error(CRASH_MESSAGE)
}

function renderLayoutAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route element={<DashboardLayout />}>
          <Route path="/dashboard" element={<CrashingPage />} />
          <Route path="/profile" element={<p>Profile page</p>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

describe('DashboardLayout when a page crashes', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  it('shows the error in place of the page and keeps the navigation', () => {
    renderLayoutAt('/dashboard')

    expect(screen.getByText(CRASH_MESSAGE)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Profile' })).toBeInTheDocument()
  })

  it('renders the next page once the user navigates away', () => {
    renderLayoutAt('/dashboard')

    fireEvent.click(screen.getByRole('link', { name: 'Profile' }))

    expect(screen.getByText('Profile page')).toBeInTheDocument()
    expect(screen.queryByText(CRASH_MESSAGE)).not.toBeInTheDocument()
  })
})
