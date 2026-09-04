import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider, hashKey } from '@tanstack/react-query'
import type { ReactNode } from 'react'

import { analyticsApi } from '@/api/analytics'
import { analyticsKeys, useAnalyticsSummary } from '../use-analytics'
import type { AnalyticsSummary } from '@/types/analytics'

vi.mock('@/api/analytics', () => ({
  analyticsApi: { getSummary: vi.fn() },
}))

const HEAD_MODE = undefined
const PRODUCTION = 'production'
const STAGING = 'staging'
const LIMIT = 20
const DEPENDENCY_TYPE = 'npm'
const SORT_BY = 'finding_count'
const SORT_ORDER = 'desc'
const FILTERS = { query: 'log4j' }
const NO_FINDINGS = 0
const RESOLVED_PROJECTS = 0

// Annotated, not inferred: an inferred fixture drops a field from the response type silently.
const summary: AnalyticsSummary = {
  total_dependencies: NO_FINDINGS,
  total_vulnerabilities: NO_FINDINGS,
  unique_packages: NO_FINDINGS,
  dependency_types: [],
  severity_distribution: {
    critical: NO_FINDINGS,
    high: NO_FINDINGS,
    medium: NO_FINDINGS,
    low: NO_FINDINGS,
  },
  resolved_projects: RESOLVED_PROJECTS,
  projects_without_release: RESOLVED_PROJECTS,
}

// Every endpoint that accepts release_environment, keyed the way its caller keys it.
const modeSensitiveKeys: [string, (releaseEnvironment?: string) => readonly unknown[]][] = [
  ['scope', (mode) => analyticsKeys.scope(mode)],
  ['summary', (mode) => analyticsKeys.summary(mode)],
  ['topDependencies', (mode) => analyticsKeys.topDependencies(LIMIT, DEPENDENCY_TYPE, mode)],
  ['dependencyTypes', (mode) => analyticsKeys.dependencyTypes(mode)],
  ['impactAnalysis', (mode) => analyticsKeys.impactAnalysis(LIMIT, mode)],
  ['hotspots', (mode) => analyticsKeys.hotspots(SORT_BY, SORT_ORDER, mode)],
  ['advancedSearch', (mode) => analyticsKeys.advancedSearch(FILTERS, mode)],
  ['vulnerabilitySearch', (mode) => analyticsKeys.vulnerabilitySearch(FILTERS, mode)],
]

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function wrapperFor(client: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

describe('analyticsKeys release mode', () => {
  it.each(modeSensitiveKeys)('%s caches each environment apart from the branch tip', (_name, key) => {
    expect(hashKey(key(HEAD_MODE))).not.toBe(hashKey(key(PRODUCTION)))
    expect(hashKey(key(PRODUCTION))).not.toBe(hashKey(key(STAGING)))
    expect(hashKey(key(PRODUCTION))).toBe(hashKey(key(PRODUCTION)))
  })

  it('leaves the keys of the endpoints that have no release mode alone', () => {
    expect(analyticsKeys.dashboardStats()).toEqual([...analyticsKeys.all, 'dashboard-stats'])
    expect(analyticsKeys.recommendations('p1')).toEqual([...analyticsKeys.all, 'recommendations', 'p1', { scanId: undefined }])
  })
})

describe('useAnalyticsSummary', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(analyticsApi.getSummary).mockResolvedValue(summary)
  })

  it('fetches the release instead of serving the branch-tip rows it already cached', async () => {
    const wrapper = wrapperFor(makeClient())

    const head = renderHook(() => useAnalyticsSummary(HEAD_MODE), { wrapper })
    await waitFor(() => expect(head.result.current.isSuccess).toBe(true))

    const release = renderHook(() => useAnalyticsSummary(PRODUCTION), { wrapper })
    await waitFor(() => expect(release.result.current.isSuccess).toBe(true))

    expect(vi.mocked(analyticsApi.getSummary).mock.calls).toEqual([[HEAD_MODE], [PRODUCTION]])
  })
})
