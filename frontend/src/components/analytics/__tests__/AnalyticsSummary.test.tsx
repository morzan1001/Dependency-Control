import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi, afterEach } from 'vitest'

import { AnalyticsSummaryCards } from '../AnalyticsSummary'
import type { AnalyticsSummary } from '@/types/analytics'

const mockUseAnalyticsSummary = vi.fn()

vi.mock('@/hooks/queries/use-analytics', () => ({
  useAnalyticsSummary: () => mockUseAnalyticsSummary(),
}))

const DEPENDENCIES_TILE = 'Total Dependencies'
const NO_FINDINGS = 0
const TOTAL_DEPENDENCIES = 10
const TOTAL_VULNERABILITIES = 2
const UNIQUE_PACKAGES = 8
const RESOLVED_PROJECTS = 40
const PROJECTS_WITHOUT_SCAN = 660
const TOTAL_PROJECTS = 700
const NONE_MISSING = 0

// Annotated, not inferred: an inferred fixture drops a field from the response type silently.
const base: AnalyticsSummary = {
  total_dependencies: TOTAL_DEPENDENCIES,
  total_vulnerabilities: TOTAL_VULNERABILITIES,
  unique_packages: UNIQUE_PACKAGES,
  dependency_types: [],
  severity_distribution: {
    critical: NO_FINDINGS,
    high: NO_FINDINGS,
    medium: NO_FINDINGS,
    low: NO_FINDINGS,
  },
  resolved_projects: RESOLVED_PROJECTS,
  projects_without_release: PROJECTS_WITHOUT_SCAN,
}

function renderCards(summary: AnalyticsSummary | undefined, isLoading = false) {
  mockUseAnalyticsSummary.mockReturnValue({ data: summary, isLoading })
  return render(<AnalyticsSummaryCards />)
}

describe('AnalyticsSummaryCards scope caption', () => {
  afterEach(() => vi.clearAllMocks())

  it('names how many projects were left out of the scope', () => {
    renderCards(base)

    expect(
      screen.getByText(
        `Counted ${RESOLVED_PROJECTS} of ${TOTAL_PROJECTS} projects; ${PROJECTS_WITHOUT_SCAN} contributed no scan to this scope.`,
      ),
    ).toBeInTheDocument()
  })

  it('stays quiet when every project contributed', () => {
    renderCards({ ...base, resolved_projects: TOTAL_PROJECTS, projects_without_release: NONE_MISSING })

    expect(screen.queryByText(/contributed no scan/)).not.toBeInTheDocument()
  })

  it('shows placeholders and no caption while the summary is still loading', () => {
    renderCards(undefined, true)

    expect(screen.queryByText(DEPENDENCIES_TILE)).not.toBeInTheDocument()
    expect(screen.queryByText(/contributed no scan/)).not.toBeInTheDocument()
  })

  // Without a release environment the backend fills projects_without_release with the projects
  // that have no usable scan at all, so wording it as a release count would state something false.
  it('does not blame the missing projects on a release they never made', () => {
    renderCards(base)

    expect(screen.queryByText(/release/i)).not.toBeInTheDocument()
  })
})
