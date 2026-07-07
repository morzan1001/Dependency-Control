import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'

import { ANALYTICS_ROUTE_PERMISSIONS } from '../lib/constants'
import { RequirePermission } from '../context'
import { AuthContext, type AuthContextType } from '../context/auth-context'

// Renders the exact /analytics route gate used in App.tsx for a user holding
// only `perms`, and reports whether they land on the Analytics page or get
// redirected to /dashboard.
function renderAnalyticsGate(perms: string[]) {
  const authValue: AuthContextType = {
    isAuthenticated: true,
    isLoading: false,
    permissions: perms,
    hasPermission: (permission: string) => perms.includes(permission),
    login: () => undefined,
    logout: () => undefined,
  }

  return render(
    <AuthContext.Provider value={authValue}>
      <MemoryRouter initialEntries={['/analytics']}>
        <Routes>
          <Route
            path="/analytics"
            element={
              <RequirePermission permission={[...ANALYTICS_ROUTE_PERMISSIONS]}>
                <div>ANALYTICS PAGE</div>
              </RequirePermission>
            }
          />
          <Route path="/dashboard" element={<div>DASHBOARD PAGE</div>} />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  )
}

describe('/analytics route permission gate', () => {
  it('lets a user with only analytics:recommendations reach the Analytics page', () => {
    // Regression: this permission was omitted from the gate, wrongly redirecting
    // users who have two working tabs (Recommendations + Update Frequency).
    renderAnalyticsGate(['analytics:recommendations'])
    expect(screen.getByText('ANALYTICS PAGE')).toBeInTheDocument()
    expect(screen.queryByText('DASHBOARD PAGE')).not.toBeInTheDocument()
  })

  it('redirects a user with only analytics:dependencies (which renders no tabs)', () => {
    // analytics:dependencies is never checked in Analytics.tsx, so passing the
    // gate would drop the user on an empty page. It must no longer grant access.
    renderAnalyticsGate(['analytics:dependencies'])
    expect(screen.getByText('DASHBOARD PAGE')).toBeInTheDocument()
    expect(screen.queryByText('ANALYTICS PAGE')).not.toBeInTheDocument()
  })

  it('still admits users with any tab-granting analytics permission', () => {
    for (const perm of ANALYTICS_ROUTE_PERMISSIONS) {
      const { unmount } = renderAnalyticsGate([perm])
      expect(screen.getByText('ANALYTICS PAGE')).toBeInTheDocument()
      unmount()
    }
  })
})
