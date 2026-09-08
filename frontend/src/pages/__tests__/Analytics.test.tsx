import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import AnalyticsPage from '../Analytics'
import { AuthContext, type AuthContextType } from '@/context/auth-context'
import { useAnalyticsMode } from '@/context/analytics-mode'
import type { AnalyticsScope } from '@/types/analytics'

const MODE_PROBE = 'analytics-mode'
const HEAD_MODE_PROBE = 'head'
const SCOPE_LABEL = 'Analytics scope'
const HEAD_MODE_LABEL = 'Latest scan'
const PRODUCTION = 'production'
const RELEASE_OPTION = `${PRODUCTION} release`
const TREE_TAB = 'Tree'
const RECOMMENDATIONS_TAB = 'Recommendations'
const HOTSPOTS_TAB = 'Hotspots'
const HEAD_ONLY_NOTE = /always reports the latest scan/
const RESOLVED_PROJECTS = 40
const PROJECTS_WITHOUT_RELEASE = 660
const OLDEST_ANALYSIS_AT = '2026-08-06T00:00:00Z'
const READ_EVERYTHING = 'analytics:read'

// Reports the release environment the tab it stands in would query with.
function ModeProbe() {
  return <span data-testid={MODE_PROBE}>{useAnalyticsMode() ?? HEAD_MODE_PROBE}</span>
}

const mockUseAnalyticsScope = vi.fn()

vi.mock('@/hooks/queries/use-analytics', () => ({
  useAnalyticsScope: (releaseEnvironment?: string) => mockUseAnalyticsScope(releaseEnvironment),
}))

vi.mock('@/components/analytics/AnalyticsSummary', () => ({
  AnalyticsSummaryCards: () => null,
  SeverityDistribution: () => null,
  DependencyTypesChart: () => null,
}))
vi.mock('@/components/analytics/DependencyStats', () => ({ DependencyStats: () => <ModeProbe /> }))
vi.mock('@/components/analytics/DependencyTree', () => ({ DependencyTree: () => <ModeProbe /> }))
vi.mock('@/components/analytics/ImpactAnalysis', () => ({ ImpactAnalysis: () => null }))
vi.mock('@/components/analytics/VulnerabilityHotspots', () => ({ VulnerabilityHotspots: () => <ModeProbe /> }))
vi.mock('@/components/analytics/CrossProjectSearch', () => ({ CrossProjectSearch: () => null }))
vi.mock('@/components/analytics/VulnerabilitySearch', () => ({ VulnerabilitySearch: () => null }))
vi.mock('@/components/analytics/Recommendations', () => ({ Recommendations: () => <ModeProbe /> }))
vi.mock('@/components/analytics/UpdateFrequency', () => ({ UpdateFrequency: () => null }))
vi.mock('@/components/analytics/UpdateFrequencyComparison', () => ({ UpdateFrequencyComparison: () => null }))
vi.mock('@/components/analytics/AnalyticsDependencyModal', () => ({ AnalyticsDependencyModal: () => null }))
vi.mock('@/components/analytics/CryptoAnalyticsTab', () => ({ CryptoAnalyticsTab: () => null }))

// Annotated, not inferred: an inferred fixture drops a field from the response type silently.
const scope: AnalyticsScope = {
  release_environments: [PRODUCTION],
  resolved_projects: RESOLVED_PROJECTS,
  projects_without_release: PROJECTS_WITHOUT_RELEASE,
  oldest_analysis_at: OLDEST_ANALYSIS_AT,
}

function renderPage() {
  const auth: AuthContextType = {
    isAuthenticated: true,
    isLoading: false,
    permissions: [READ_EVERYTHING],
    hasPermission: (permission: string) => permission === READ_EVERYTHING,
    login: () => undefined,
    logout: () => undefined,
  }

  return render(
    <AuthContext.Provider value={auth}>
      <AnalyticsPage />
    </AuthContext.Provider>,
  )
}

function pickRelease() {
  fireEvent.click(screen.getByLabelText(SCOPE_LABEL))
  fireEvent.click(screen.getByRole('option', { name: RELEASE_OPTION }))
}

function openTab(name: string) {
  // Radix selects a tab on mousedown, so a bare click leaves the panel where it was.
  fireEvent.mouseDown(screen.getByRole('tab', { name }))
}

beforeEach(() => {
  vi.clearAllMocks()
  mockUseAnalyticsScope.mockReturnValue({ data: scope })
})

describe('Analytics release mode across tabs', () => {
  it('reports the picked release on a tab whose endpoints accept it', () => {
    renderPage()
    expect(screen.getByTestId(MODE_PROBE)).toHaveTextContent(HEAD_MODE_PROBE)

    pickRelease()

    expect(screen.getByTestId(MODE_PROBE)).toHaveTextContent(PRODUCTION)
  })

  it.each([TREE_TAB, RECOMMENDATIONS_TAB])(
    'falls back to the latest scan on the %s tab and says the switch is off',
    (tab) => {
      renderPage()
      pickRelease()

      openTab(tab)

      expect(screen.getByTestId(MODE_PROBE)).toHaveTextContent(HEAD_MODE_PROBE)
      expect(screen.getByLabelText(SCOPE_LABEL)).toBeDisabled()
      expect(screen.getByLabelText(SCOPE_LABEL)).toHaveTextContent(HEAD_MODE_LABEL)
      expect(screen.getByText(HEAD_ONLY_NOTE)).toBeInTheDocument()
    },
  )

  it('asks the scope endpoint for head coverage while a head-only tab is open', () => {
    renderPage()
    pickRelease()
    expect(mockUseAnalyticsScope).toHaveBeenCalledWith(PRODUCTION)

    openTab(TREE_TAB)

    expect(mockUseAnalyticsScope).toHaveBeenLastCalledWith(undefined)
  })

  it('restores the release once a tab that can report it is open again', () => {
    renderPage()
    pickRelease()
    openTab(TREE_TAB)

    openTab(HOTSPOTS_TAB)

    expect(screen.getByTestId(MODE_PROBE)).toHaveTextContent(PRODUCTION)
    expect(screen.getByLabelText(SCOPE_LABEL)).toBeEnabled()
    expect(screen.queryByText(HEAD_ONLY_NOTE)).not.toBeInTheDocument()
  })
})
