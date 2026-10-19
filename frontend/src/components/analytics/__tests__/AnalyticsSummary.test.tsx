import { fireEvent, render, screen } from '@testing-library/react'
import { describe, it, expect, vi, afterEach } from 'vitest'

import { AnalyticsSummaryCards, DependencyTypesChart, SeverityDistribution } from '../AnalyticsSummary'
import { AnalyticsModeContext } from '@/context/analytics-mode'
import { SEVERITY_CHART_COLORS } from '@/lib/finding-utils'
import type { AnalyticsSummary } from '@/types/analytics'

const mockUseAnalyticsSummary = vi.fn()

vi.mock('@/hooks/queries/use-analytics', () => ({
  useAnalyticsSummary: (releaseEnvironment?: string) => mockUseAnalyticsSummary(releaseEnvironment),
}))

const DEPENDENCIES_TILE = 'Total Dependencies'
const NO_FINDINGS = 0
const TOTAL_DEPENDENCIES = 10
const TOTAL_VULNERABILITIES = 2
const UNIQUE_PACKAGES = 8
const HEAD_MODE = undefined
const PRODUCTION = 'production'

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
}

function renderCards(
  summary: AnalyticsSummary | undefined,
  isLoading = false,
  releaseEnvironment: string | undefined = HEAD_MODE,
) {
  mockUseAnalyticsSummary.mockReturnValue({ data: summary, isLoading })
  return render(
    <AnalyticsModeContext.Provider value={releaseEnvironment}>
      <AnalyticsSummaryCards />
    </AnalyticsModeContext.Provider>,
  )
}

describe('AnalyticsSummaryCards', () => {
  afterEach(() => vi.clearAllMocks())

  it('counts the dependencies the summary reported', () => {
    renderCards(base)

    expect(screen.getByText(DEPENDENCIES_TILE)).toBeInTheDocument()
    expect(screen.getByText(String(TOTAL_DEPENDENCIES))).toBeInTheDocument()
  })

  it('shows placeholders instead of tiles while the summary is still loading', () => {
    renderCards(undefined, true)

    expect(screen.queryByText(DEPENDENCIES_TILE)).not.toBeInTheDocument()
  })

  it('reports the branch tip while no environment is selected', () => {
    renderCards(base)

    expect(mockUseAnalyticsSummary).toHaveBeenCalledWith(HEAD_MODE)
  })

  it('reports the selected environment instead of the branch tip', () => {
    renderCards(base, false, PRODUCTION)

    expect(mockUseAnalyticsSummary).toHaveBeenCalledWith(PRODUCTION)
  })
})

describe('analytics summary load error', () => {
  const error = Object.assign(new Error('Request failed'), {
    response: { status: 403, data: { detail: 'Not enough permissions' } },
  })
  const refetch = vi.fn()

  afterEach(() => vi.clearAllMocks())

  it('says the summary failed instead of showing zero tiles, and retries it', () => {
    mockUseAnalyticsSummary.mockReturnValue({ data: undefined, isLoading: false, error, refetch })
    render(<AnalyticsSummaryCards />)

    expect(screen.getByRole('alert')).toHaveTextContent('Not enough permissions')
    expect(screen.queryByText(DEPENDENCIES_TILE)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(refetch).toHaveBeenCalled()
  })

  it('draws no dependency-type chart for a summary that failed to load', () => {
    mockUseAnalyticsSummary.mockReturnValue({ data: undefined, isLoading: false, error, refetch })
    const { container } = render(<DependencyTypesChart />)

    expect(container).toBeEmptyDOMElement()
  })

  it('still says no dependencies were found for a summary without any', () => {
    mockUseAnalyticsSummary.mockReturnValue({ data: base, isLoading: false, error: null, refetch })
    render(<DependencyTypesChart />)

    expect(screen.getByText('No dependencies found')).toBeInTheDocument()
  })
})

describe('SeverityDistribution', () => {
  it('colours its bar and legend from the palette the other severity charts use', () => {
    mockUseAnalyticsSummary.mockReturnValue({
      data: { ...base, severity_distribution: { critical: 1, high: 2, medium: 3, low: 4, negligible: 5, info: 6, unknown: 7 } },
      isLoading: false,
    })
    render(<SeverityDistribution />)

    const shown = [['Critical', 1], ['High', 2], ['Medium', 3], ['Low', 4], ['Negligible', 5], ['Info', 6], ['Unknown', 7]] as const
    for (const [label, count] of shown) {
      const color = SEVERITY_CHART_COLORS[label.toUpperCase() as keyof typeof SEVERITY_CHART_COLORS]
      expect(screen.getByTitle(`${label}: ${count}`)).toHaveStyle({ backgroundColor: color })
      expect(screen.getByText(label).previousElementSibling).toHaveStyle({ backgroundColor: color })
    }
  })
})

describe('AnalyticsSummaryCards vulnerability colour', () => {
  afterEach(() => vi.clearAllMocks())

  it('writes a vulnerability total in the critical severity colour', () => {
    renderCards(base)

    expect(screen.getByText(String(TOTAL_VULNERABILITIES))).toHaveClass('text-severity-critical')
  })
})
