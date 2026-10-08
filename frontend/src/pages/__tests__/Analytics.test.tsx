import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, useSearchParams } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import AnalyticsPage from '../Analytics'
import { AuthContext, type AuthContextType } from '@/context/auth-context'
import { useAnalyticsMode } from '@/context/analytics-mode'
import { useAnalyticsView } from '@/components/crypto/analytics/useAnalyticsView'
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
vi.mock('@/components/analytics/VulnerabilitySearch', () => ({
  VulnerabilitySearch: () => <span data-testid="vuln-severity">{useSearchParams()[0].get('severity') ?? 'all'}</span>,
}))
vi.mock('@/components/analytics/Recommendations', () => ({ Recommendations: () => <ModeProbe /> }))
vi.mock('@/components/analytics/UpdateFrequency', () => ({ UpdateFrequency: () => null }))
vi.mock('@/components/analytics/UpdateFrequencyComparison', () => ({ UpdateFrequencyComparison: () => null }))
vi.mock('@/components/analytics/AnalyticsDependencyModal', () => ({ AnalyticsDependencyModal: () => null }))
vi.mock('@/components/analytics/CryptoAnalyticsTab', () => ({
  CryptoAnalyticsTab: () => <span data-testid="crypto-view">{useAnalyticsView()}</span>,
}))
vi.mock('@/components/compliance/ComplianceReportsPanel', () => ({
  ComplianceReportsPanel: () => <span data-testid="compliance-reports" />,
}))

// Annotated, not inferred: an inferred fixture drops a field from the response type silently.
const scope: AnalyticsScope = {
  release_environments: [PRODUCTION],
  resolved_projects: RESOLVED_PROJECTS,
  projects_without_release: PROJECTS_WITHOUT_RELEASE,
  oldest_analysis_at: OLDEST_ANALYSIS_AT,
}

function renderPage(url = '/analytics') {
  const auth: AuthContextType = {
    isAuthenticated: true,
    isLoading: false,
    permissions: [READ_EVERYTHING],
    hasPermission: (permission: string) => permission === READ_EVERYTHING,
    login: () => undefined,
    logout: () => undefined,
    signedOut: false,
  }

  return render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter initialEntries={[url]}>
        <AnalyticsPage />
      </MemoryRouter>
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

describe('Analytics deep link', () => {
  it('opens the tab the link names', () => {
    renderPage('/analytics?tab=search-vulns&severity=CRITICAL')

    expect(screen.getByRole('tab', { name: 'Vulnerabilities' })).toHaveAttribute('aria-selected', 'true')
  })

  it('opens the first tab for a tab the user cannot see', () => {
    renderPage('/analytics?tab=no-such-tab')

    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true')
  })

  it('keeps the crypto view across a tab round trip', () => {
    renderPage('/analytics?tab=cryptography&analytics_view=heatmap')

    openTab(HOTSPOTS_TAB)
    openTab('Cryptography')

    expect(screen.getByTestId('crypto-view')).toHaveTextContent('heatmap')
  })

  it('presets the severity a link names only until the user switches tabs', () => {
    renderPage('/analytics?tab=search-vulns&severity=CRITICAL')
    expect(screen.getByTestId('vuln-severity')).toHaveTextContent('CRITICAL')

    openTab(HOTSPOTS_TAB)
    openTab('Vulnerabilities')

    expect(screen.getByTestId('vuln-severity')).toHaveTextContent('all')
  })
})

describe('Analytics compliance reports', () => {
  it('open from a tab of their own', () => {
    renderPage('/analytics?tab=compliance')

    expect(screen.getByRole('tab', { name: 'Compliance' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('compliance-reports')).toBeInTheDocument()
  })

  it('leave the release switch off, since each report picks its own scans', () => {
    renderPage()
    pickRelease()

    openTab('Compliance')

    expect(screen.getByLabelText(SCOPE_LABEL)).toBeDisabled()
    expect(screen.getByText(HEAD_ONLY_NOTE)).toBeInTheDocument()
  })
})

