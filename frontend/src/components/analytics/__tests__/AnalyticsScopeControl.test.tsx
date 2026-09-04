import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, afterEach } from 'vitest'

import { AnalyticsScopeControl } from '../AnalyticsScopeControl'
import type { AnalyticsScope } from '@/types/analytics'

const mockUseAnalyticsScope = vi.fn()

vi.mock('@/hooks/queries/use-analytics', () => ({
  useAnalyticsScope: (releaseEnvironment?: string) => mockUseAnalyticsScope(releaseEnvironment),
}))

const SCOPE_LABEL = 'Analytics scope'
const HEAD_MODE = undefined
const HEAD_MODE_LABEL = 'Latest scan'
const PRODUCTION = 'production'
const STAGING = 'staging'
const RESOLVED_PROJECTS = 40
const PROJECTS_WITHOUT_SCAN = 660
const TOTAL_PROJECTS = 700
const NONE_MISSING = 0

// Annotated, not inferred: an inferred fixture drops a field from the response type silently.
const base: AnalyticsScope = {
  release_environments: [PRODUCTION, STAGING],
  resolved_projects: RESOLVED_PROJECTS,
  projects_without_release: PROJECTS_WITHOUT_SCAN,
}

function renderControl(scope: AnalyticsScope | undefined, releaseEnvironment: string | undefined = HEAD_MODE) {
  mockUseAnalyticsScope.mockReturnValue({ data: scope })
  const onChange = vi.fn()
  render(<AnalyticsScopeControl releaseEnvironment={releaseEnvironment} onChange={onChange} />)
  return { onChange }
}

describe('AnalyticsScopeControl mode switch', () => {
  afterEach(() => vi.clearAllMocks())

  it('starts on the branch tip', () => {
    renderControl(base)

    expect(screen.getByLabelText(SCOPE_LABEL)).toHaveTextContent(HEAD_MODE_LABEL)
  })

  it('offers one entry per environment any project in scope was released to', () => {
    renderControl(base)

    fireEvent.click(screen.getByLabelText(SCOPE_LABEL))

    expect(screen.getByRole('option', { name: `${PRODUCTION} release` })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: `${STAGING} release` })).toBeInTheDocument()
  })

  it('reports the environment the user picked', () => {
    const { onChange } = renderControl(base)

    fireEvent.click(screen.getByLabelText(SCOPE_LABEL))
    fireEvent.click(screen.getByRole('option', { name: `${STAGING} release` }))

    expect(onChange).toHaveBeenCalledWith(STAGING)
  })

  it('reports the branch tip rather than the sentinel when the user switches back', () => {
    const { onChange } = renderControl(base, PRODUCTION)

    fireEvent.click(screen.getByLabelText(SCOPE_LABEL))
    fireEvent.click(screen.getByRole('option', { name: HEAD_MODE_LABEL }))

    expect(onChange).toHaveBeenCalledWith(HEAD_MODE)
  })

  it('asks the scope endpoint about the mode it is in, so the counters follow the switch', () => {
    renderControl(base, PRODUCTION)

    expect(mockUseAnalyticsScope).toHaveBeenCalledWith(PRODUCTION)
  })

  it('stays away entirely when nothing in scope was ever released', () => {
    renderControl({ ...base, release_environments: [] })

    expect(screen.queryByLabelText(SCOPE_LABEL)).not.toBeInTheDocument()
  })
})

describe('AnalyticsScopeControl coverage caption', () => {
  afterEach(() => vi.clearAllMocks())

  it('names how many projects were left out of the scope', () => {
    renderControl(base)

    expect(
      screen.getByText(
        `Counted ${RESOLVED_PROJECTS} of ${TOTAL_PROJECTS} projects; ${PROJECTS_WITHOUT_SCAN} contributed no scan to this scope.`,
      ),
    ).toBeInTheDocument()
  })

  // The bare-list tabs have their own permissions and report no counters, so the caption cannot
  // depend on the mode switch being there.
  it('is shown even where no environment exists to switch to', () => {
    renderControl({ ...base, release_environments: [] })

    expect(screen.getByText(/contributed no scan/)).toBeInTheDocument()
  })

  it('stays quiet when every project contributed', () => {
    renderControl({ ...base, resolved_projects: TOTAL_PROJECTS, projects_without_release: NONE_MISSING })

    expect(screen.queryByText(/contributed no scan/)).not.toBeInTheDocument()
  })

  it('stays quiet while the scope is still loading', () => {
    renderControl(undefined)

    expect(screen.queryByText(/contributed no scan/)).not.toBeInTheDocument()
  })

  // Without a release environment the backend fills projects_without_release with the projects
  // that have no usable scan at all, so wording it as a release count would state something false.
  it('does not blame the missing projects on a release they never made', () => {
    renderControl({ ...base, release_environments: [] })

    expect(screen.queryByText(/release/i)).not.toBeInTheDocument()
  })
})
