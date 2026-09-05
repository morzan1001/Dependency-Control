import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ProjectOverview } from '../ProjectOverview'
import type { LatestProjectRelease } from '@/hooks/queries/use-releases'
import type { ReleaseItem } from '@/types/release'
import type { EnhancedStats, ScanWithReleases } from '@/types/scan'

const PROJECT_ID = 'p1'
const MAIN_BRANCH = 'main'

const mockUseProjectScans = vi.fn()
const mockUseScan = vi.fn()
const mockUseScanResults = vi.fn()
const mockUseLatestProjectRelease = vi.fn()
const mockUseProjectWaivers = vi.fn()
const mockNavigate = vi.fn()

vi.mock('@/hooks/queries/use-scans', () => ({
  useProjectScans: (...args: unknown[]) => mockUseProjectScans(...args),
  useScan: (...args: unknown[]) => mockUseScan(...args),
  useScanResults: (...args: unknown[]) => mockUseScanResults(...args),
}))

vi.mock('@/hooks/queries/use-releases', () => ({
  useLatestProjectRelease: (...args: unknown[]) => mockUseLatestProjectRelease(...args),
}))

vi.mock('@/hooks/queries/use-waivers', () => ({
  useProjectWaivers: (...args: unknown[]) => mockUseProjectWaivers(...args),
}))

vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}))

// Isolate the gating logic: render a probe instead of the real dashboard.
vi.mock('@/components/ThreatIntelligenceDashboard', () => ({
  ThreatIntelligenceDashboard: () => <div data-testid="threat-intel-dashboard" />,
}))

// recharts is heavy in jsdom; stub the pieces used so gating is what we test.
vi.mock('recharts', () => {
  const Passthrough = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>
  return {
    ResponsiveContainer: Passthrough,
    LineChart: Passthrough,
    BarChart: Passthrough,
    PieChart: Passthrough,
    Line: () => null,
    Bar: () => null,
    Pie: () => null,
    Cell: () => null,
    XAxis: () => null,
    YAxis: () => null,
    CartesianGrid: () => null,
    Tooltip: () => null,
    Legend: () => null,
  }
})

function makeScan(overrides: Partial<ScanWithReleases>, stats: EnhancedStats): ScanWithReleases {
  return {
    id: 'scan-1',
    project_id: PROJECT_ID,
    branch: MAIN_BRANCH,
    status: 'completed',
    is_rescan: false,
    is_release: false,
    releases: [],
    created_at: '2026-07-01T00:00:00Z',
    stats,
    ...overrides,
  }
}

// Annotated, not inferred: an inferred fixture drops a field from the hook's type silently.
const noReleases: LatestProjectRelease = { latestRelease: undefined, hasReleases: false, isLoading: false }
const releasesUnknown: LatestProjectRelease = { latestRelease: undefined, hasReleases: false, isLoading: true }

function renderOverview(
  scans: ScanWithReleases[],
  selectedBranches: string[] = [MAIN_BRANCH],
  releases: LatestProjectRelease = noReleases,
  offPageScans: ScanWithReleases[] = [],
) {
  const byId = new Map([...scans, ...offPageScans].map((scan) => [scan.id, scan]))
  mockUseProjectScans.mockReturnValue({ data: scans, isLoading: false })
  mockUseScan.mockImplementation((scanId: string) => ({ data: byId.get(scanId) }))
  mockUseScanResults.mockReturnValue({ data: [] })
  mockUseLatestProjectRelease.mockReturnValue(releases)
  mockUseProjectWaivers.mockReturnValue({ data: undefined })
  return render(<ProjectOverview projectId={PROJECT_ID} selectedBranches={selectedBranches} />)
}

beforeEach(() => vi.clearAllMocks())

describe('ProjectOverview - ThreatIntelligenceDashboard gating', () => {
  it('renders the dashboard when reachability analysis exists with zero KEV/high-EPSS', () => {
    // Gating keys off the canonical analyzed_count / unreachable_count fields.
    const scan = makeScan(
      {},
      {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        unknown: 0,
        reachability: {
          analyzed_count: 200,
          reachable_count: 0,
          confirmed_reachable_count: 0,
          likely_reachable_count: 0,
          unreachable_count: 150,
          unknown_count: 50,
          reachable_critical: 0,
          reachable_high: 0,
        },
      },
    )
    renderOverview([scan])
    expect(screen.getByTestId('threat-intel-dashboard')).toBeInTheDocument()
  })

  it('renders the dashboard for medium-EPSS-only threat intel (no KEV/high-EPSS)', () => {
    const scan = makeScan(
      {},
      {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        unknown: 0,
        threat_intel: {
          kev_count: 0,
          kev_ransomware_count: 0,
          high_epss_count: 0,
          medium_epss_count: 5,
          avg_epss_score: 0.05,
          max_epss_score: 0.09,
          weaponized_count: 0,
          active_exploitation_count: 0,
        },
      },
    )
    renderOverview([scan])
    expect(screen.getByTestId('threat-intel-dashboard')).toBeInTheDocument()
  })

  it('does NOT render the dashboard when there is no enrichment data', () => {
    const scan = makeScan(
      {},
      { critical: 2, high: 1, medium: 0, low: 0, info: 0, unknown: 0 },
    )
    renderOverview([scan])
    expect(screen.queryByTestId('threat-intel-dashboard')).not.toBeInTheDocument()
  })
})

describe('ProjectOverview - multi-branch headline counts (W8)', () => {
  const branchScans = [
    makeScan({ id: 's-main', branch: 'main' }, { critical: 6, high: 11, risk_score: 40 }),
    makeScan({ id: 's-a', branch: 'feature-a' }, { critical: 5, high: 7, risk_score: 12 }),
    makeScan({ id: 's-b', branch: 'feature-b' }, { critical: 4, high: 6, risk_score: 12 }),
  ]

  it('shows the worst branch, not the sum, when several branches are selected', () => {
    renderOverview(branchScans, ['main', 'feature-a', 'feature-b'])

    expect(screen.getByText('6')).toBeInTheDocument()
    expect(screen.getByText('11')).toBeInTheDocument()
    // Summing across branches counts every shared CVE once per branch: 15 critical / 24 high.
    expect(screen.queryByText('15')).not.toBeInTheDocument()
    expect(screen.queryByText('24')).not.toBeInTheDocument()
  })

  it('names the branch the headline numbers come from', () => {
    renderOverview(branchScans, ['main', 'feature-a', 'feature-b'])

    expect(screen.getAllByText(/Branch main —/).length).toBeGreaterThan(0)
  })
})

describe('ProjectOverview - headline numbers after a failed rescan', () => {
  const HEAD_SCAN_ID = 's-main'
  const RESCAN_ID = 's-main-rescan'
  const COMPLETE_CRITICAL = 42
  const PARTIAL_CRITICAL = 337

  it('keeps the complete count rather than what a failed rescan managed to persist', () => {
    // The page shows no failure of its own, so a partial count here reads as the security posture.
    renderOverview([
      makeScan(
        {
          id: HEAD_SCAN_ID,
          latest_rescan_id: RESCAN_ID,
          latest_run: { scan_id: RESCAN_ID, status: 'failed', stats: { critical: PARTIAL_CRITICAL } },
        },
        { critical: COMPLETE_CRITICAL },
      ),
    ])

    expect(screen.getByText(String(COMPLETE_CRITICAL))).toBeInTheDocument()
    expect(screen.queryByText(String(PARTIAL_CRITICAL))).not.toBeInTheDocument()
  })
})

describe('ProjectOverview - the branch headline is the branch tip', () => {
  const TIP_SCAN_ID = 's-tip'
  const OLD_COMMIT_SCAN_ID = 's-old-commit'
  const RESCAN_ID = 's-rescan-of-old-commit'
  const TIP_BUILT_AT = '2026-08-10T00:00:00Z'
  const OLD_COMMIT_BUILT_AT = '2026-08-01T00:00:00Z'
  const RESCAN_RAN_AT = '2026-09-01T00:00:00Z'
  const TIP_CRITICAL = 11
  const OLD_COMMIT_CRITICAL = 77

  it('ignores a rescan of an older commit that ran after the tip was built', () => {
    // A rescan carries today's date over an older commit, so ordering by time alone puts the
    // released commit's numbers under the branch name.
    renderOverview([
      makeScan({ id: TIP_SCAN_ID, created_at: TIP_BUILT_AT }, { critical: TIP_CRITICAL }),
      makeScan({ id: OLD_COMMIT_SCAN_ID, created_at: OLD_COMMIT_BUILT_AT }, { critical: OLD_COMMIT_CRITICAL }),
      makeScan(
        { id: RESCAN_ID, created_at: RESCAN_RAN_AT, is_rescan: true },
        { critical: OLD_COMMIT_CRITICAL },
      ),
    ])

    expect(screen.getByText(String(TIP_CRITICAL))).toBeInTheDocument()
    expect(screen.queryByText(String(OLD_COMMIT_CRITICAL))).not.toBeInTheDocument()
  })
})

describe('ProjectOverview - release tile', () => {
  const PRODUCTION = 'production'
  const STAGING = 'staging'
  const RELEASE_VERSION = 'v1.2.3'
  const STAGING_VERSION = 'v1.3.0-rc1'
  const RELEASED_AT = '2026-08-01T00:00:00Z'
  const HEAD_CREATED_AT = '2026-09-01T00:00:00Z'
  const RETIRED_BRANCH = 'release-1.0'
  const SECOND_BRANCH = 'feature-b'
  const HEAD_SCAN_ID = 's-head'
  const HEAD_RESCAN_ID = 's-head-rescan'
  const RELEASE_SCAN_ID = 's-release'
  const RELEASE_RESCAN_ID = 's-release-rescan'
  const OFF_PAGE_SCAN_ID = 's-off-page'
  const HEAD_CRITICAL = 9
  const HEAD_HIGH = 9
  const HEAD_RESCANNED_CRITICAL = 4
  const RELEASE_CRITICAL = 2
  const RELEASE_HIGH = 3
  const RESCANNED_CRITICAL = 1
  const OFF_PAGE_CRITICAL = 5
  const SECOND_BRANCH_CRITICAL = 3
  const SECOND_BRANCH_HIGH = 3
  const CRITICAL_TILE = 'Critical Issues'
  const HIGH_TILE = 'High Issues'
  const CRITICAL_SEVERITY = 'CRITICAL'
  const SHOW_RELEASE_BUTTON = 'Show release numbers'
  const SHOW_HEAD_BUTTON = 'Show HEAD numbers'
  const RELEASE_TILE_TITLE = 'Latest Release'
  const NOT_ANALYSED_TEXT = 'Nothing in its rescan chain has finished analysing'
  const CHAIN_BOUNDED_TEXT = 'Rescan chain longer than the walk follows — a newer analysis may exist'
  const GENERIC_RELEASE_LABEL = 'Release'

  function findingsUrl(scanId: string, severity: string): string {
    return `/projects/${PROJECT_ID}/scans/${scanId}?severity=${severity}`
  }

  function releaseList(overrides: Partial<ReleaseItem> = {}): LatestProjectRelease {
    const item: ReleaseItem = {
      scan_id: RELEASE_SCAN_ID,
      project_id: PROJECT_ID,
      environment: PRODUCTION,
      version: RELEASE_VERSION,
      released_at: RELEASED_AT,
      commit_hash: null,
      branch: MAIN_BRANCH,
      scan_status: 'completed',
      analysis_scan_id: RELEASE_SCAN_ID,
      analysis_chain_bounded: false,
      ...overrides,
    }
    return { latestRelease: item, hasReleases: true, isLoading: false }
  }

  const head = makeScan(
    { id: HEAD_SCAN_ID, created_at: HEAD_CREATED_AT },
    { critical: HEAD_CRITICAL, high: HEAD_HIGH },
  )
  const release = makeScan(
    {
      id: RELEASE_SCAN_ID,
      created_at: RELEASED_AT,
      is_release: true,
      releases: [{ environment: PRODUCTION, version: RELEASE_VERSION, released_at: RELEASED_AT }],
    },
    { critical: RELEASE_CRITICAL, high: RELEASE_HIGH },
  )
  // The endpoint follows the rescan chain itself, so the row names the rescan as the analysis.
  const releaseRescan = makeScan(
    { id: RELEASE_RESCAN_ID, created_at: HEAD_CREATED_AT, is_rescan: true },
    { critical: RESCANNED_CRITICAL, high: 0 },
  )
  const releaseRescanQueued = makeScan(
    {
      id: RELEASE_SCAN_ID,
      created_at: RELEASED_AT,
      is_release: true,
      releases: [{ environment: PRODUCTION, version: RELEASE_VERSION, released_at: RELEASED_AT }],
      // A queued rescan has analysed nothing yet, so its summary carries no stats.
      latest_run: { scan_id: RELEASE_RESCAN_ID, status: 'pending' },
    },
    { critical: RELEASE_CRITICAL, high: RELEASE_HIGH },
  )
  const releaseRescanWithoutStats = makeScan(
    {
      id: RELEASE_SCAN_ID,
      created_at: RELEASED_AT,
      is_release: true,
      releases: [{ environment: PRODUCTION, version: RELEASE_VERSION, released_at: RELEASED_AT }],
      latest_run: { scan_id: RELEASE_RESCAN_ID, status: 'completed', stats: null },
    },
    { critical: RELEASE_CRITICAL, high: RELEASE_HIGH },
  )

  // The tiles are scoped with within() because the numbers are not unique on the page:
  // in the `head` fixture Critical Issues and High Issues both render 9, and after the
  // switch the release's Critical Issues (2) collides with Total Scans (2 scans loaded).
  // getByText returns the CardTitle <h3>; this repo's Card is a plain div with no data-slot,
  // so `rounded-lg` is the nearest identifying ancestor class.
  function tile(title: string) {
    return screen.getByText(title).closest('.rounded-lg') as HTMLElement
  }

  it('names the latest release', () => {
    renderOverview([head, release], [MAIN_BRANCH], releaseList())

    expect(screen.getByLabelText(`Release ${RELEASE_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()
  })

  it('names whichever environment the release went to, rather than assuming production', () => {
    renderOverview(
      [head, release],
      [MAIN_BRANCH],
      releaseList({ environment: STAGING, version: STAGING_VERSION }),
    )

    expect(screen.getByLabelText(`Release ${STAGING_VERSION} in ${STAGING}`)).toBeInTheDocument()
  })

  it('takes the release the endpoint names, not the newest flagged scan on the page', () => {
    const newerFlagged = makeScan(
      {
        id: 's-newer-flagged',
        created_at: HEAD_CREATED_AT,
        is_release: true,
        releases: [{ environment: STAGING, version: STAGING_VERSION, released_at: HEAD_CREATED_AT }],
      },
      { critical: RELEASE_CRITICAL, high: RELEASE_HIGH },
    )
    renderOverview([head, release, newerFlagged], [MAIN_BRANCH], releaseList())

    expect(screen.getByLabelText(`Release ${RELEASE_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()
    expect(screen.queryByLabelText(`Release ${STAGING_VERSION} in ${STAGING}`)).not.toBeInTheDocument()
  })

  it('shows no tile at all on a project that reports no release', () => {
    // An empty tile reads as a missing report rather than as a repo that does not release.
    renderOverview([head])

    expect(screen.queryByText(RELEASE_TILE_TITLE)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: SHOW_RELEASE_BUTTON })).not.toBeInTheDocument()
  })

  it('waits for the row before falling back to a flagged scan, so no nameless badge flashes up', () => {
    const flaggedOnly = makeScan(
      { id: 's-flagged', created_at: RELEASED_AT, is_release: true },
      { critical: RELEASE_CRITICAL, high: RELEASE_HIGH },
    )
    renderOverview([head, flaggedOnly], [MAIN_BRANCH], releasesUnknown)

    expect(screen.queryByText(RELEASE_TILE_TITLE)).not.toBeInTheDocument()
  })

  it('shows the tile once the project reports one', () => {
    renderOverview([head, release], [MAIN_BRANCH], releaseList())

    expect(screen.getByText(RELEASE_TILE_TITLE)).toBeInTheDocument()
    expect(screen.queryByText(CHAIN_BOUNDED_TEXT)).not.toBeInTheDocument()
  })

  it('says the analysis may be stale when the rescan walk stopped at its bound', () => {
    renderOverview([head, release], [MAIN_BRANCH], releaseList({ analysis_chain_bounded: true }))

    expect(screen.getByText(CHAIN_BOUNDED_TEXT)).toBeInTheDocument()
  })

  it('offers no numbers for a release whose analysis has not finished', () => {
    renderOverview([head], [MAIN_BRANCH], releaseList({ analysis_scan_id: null }))

    expect(screen.getByLabelText(`Release ${RELEASE_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()
    expect(screen.getByText(NOT_ANALYSED_TEXT)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: SHOW_RELEASE_BUTTON })).not.toBeInTheDocument()
  })

  it('shows HEAD numbers until the switch is used', () => {
    renderOverview([head, release], [MAIN_BRANCH], releaseList())

    expect(within(tile(CRITICAL_TILE)).getByText(String(HEAD_CRITICAL))).toBeInTheDocument()
    expect(within(tile(HIGH_TILE)).getByText(String(HEAD_HIGH))).toBeInTheDocument()
  })

  it('switches the headline numbers to the release', () => {
    renderOverview([head, release], [MAIN_BRANCH], releaseList())

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))

    expect(within(tile(CRITICAL_TILE)).getByText(String(RELEASE_CRITICAL))).toBeInTheDocument()
    expect(within(tile(HIGH_TILE)).getByText(String(RELEASE_HIGH))).toBeInTheDocument()
    expect(screen.getByRole('button', { name: SHOW_HEAD_BUTTON })).toBeInTheDocument()
  })

  it('names the environment the switched numbers describe, not just the branch', () => {
    renderOverview([head, release], [MAIN_BRANCH], releaseList())

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))

    expect(
      screen.getAllByText(`Release in ${PRODUCTION} on ${MAIN_BRANCH} — click to view findings`).length,
    ).toBeGreaterThan(0)
    expect(screen.queryByText(`Branch ${MAIN_BRANCH} — click to view findings`)).not.toBeInTheDocument()
  })

  it('reads the analysis the release row names, not the released scan', () => {
    renderOverview(
      [head, release],
      [MAIN_BRANCH],
      releaseList({ analysis_scan_id: RELEASE_RESCAN_ID }),
      [releaseRescan],
    )

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))
    fireEvent.click(tile(CRITICAL_TILE))

    expect(within(tile(CRITICAL_TILE)).getByText(String(RESCANNED_CRITICAL))).toBeInTheDocument()
    expect(mockNavigate).toHaveBeenCalledWith(findingsUrl(RELEASE_RESCAN_ID, CRITICAL_SEVERITY))
  })

  it('keeps the release numbers while its rescan is still queued', () => {
    renderOverview([head, releaseRescanQueued], [MAIN_BRANCH], releaseList())

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))

    expect(within(tile(CRITICAL_TILE)).getByText(String(RELEASE_CRITICAL))).toBeInTheDocument()
  })

  it('sends the tile to the release whose numbers it shows, not to the queued rescan', () => {
    renderOverview([head, releaseRescanQueued], [MAIN_BRANCH], releaseList())

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))
    fireEvent.click(tile(CRITICAL_TILE))

    expect(mockNavigate).toHaveBeenCalledWith(findingsUrl(RELEASE_SCAN_ID, CRITICAL_SEVERITY))
    expect(mockUseScanResults).toHaveBeenLastCalledWith(RELEASE_SCAN_ID)
  })

  it('keeps release numbers and release identity together when a finished rescan reports none', () => {
    renderOverview([head, releaseRescanWithoutStats], [MAIN_BRANCH], releaseList())

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))
    fireEvent.click(tile(CRITICAL_TILE))

    expect(within(tile(CRITICAL_TILE)).getByText(String(RELEASE_CRITICAL))).toBeInTheDocument()
    expect(mockNavigate).toHaveBeenCalledWith(findingsUrl(RELEASE_SCAN_ID, CRITICAL_SEVERITY))
  })

  it('reads the HEAD rescan numbers too, so the switch compares like with like', () => {
    const headRescanned = makeScan(
      {
        id: HEAD_SCAN_ID,
        created_at: HEAD_CREATED_AT,
        latest_run: {
          scan_id: HEAD_RESCAN_ID,
          status: 'completed',
          stats: { critical: HEAD_RESCANNED_CRITICAL, high: 0 },
        },
      },
      { critical: HEAD_CRITICAL, high: HEAD_HIGH },
    )
    renderOverview([headRescanned, release], [MAIN_BRANCH], releaseList())

    expect(within(tile(CRITICAL_TILE)).getByText(String(HEAD_RESCANNED_CRITICAL))).toBeInTheDocument()

    fireEvent.click(tile(CRITICAL_TILE))

    expect(mockNavigate).toHaveBeenCalledWith(findingsUrl(HEAD_RESCAN_ID, CRITICAL_SEVERITY))
  })

  it('turns the branch tabs off while release numbers are shown', () => {
    const otherBranch = makeScan(
      { id: 's-second-branch', branch: SECOND_BRANCH, created_at: HEAD_CREATED_AT },
      { critical: SECOND_BRANCH_CRITICAL, high: SECOND_BRANCH_HIGH },
    )
    renderOverview([head, release, otherBranch], [MAIN_BRANCH, SECOND_BRANCH], releaseList())

    expect(screen.getByRole('tab', { name: MAIN_BRANCH })).toBeEnabled()

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))

    expect(screen.getByRole('tab', { name: MAIN_BRANCH })).toBeDisabled()
    expect(screen.getByRole('tab', { name: SECOND_BRANCH })).toBeDisabled()
  })

  it('counts a scan whose release record has not landed yet', () => {
    const flaggedOnly = makeScan(
      { id: 's-flagged', created_at: RELEASED_AT, is_release: true },
      { critical: RELEASE_CRITICAL, high: RELEASE_HIGH },
    )
    renderOverview([head, flaggedOnly])

    expect(screen.getByLabelText(GENERIC_RELEASE_LABEL)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))

    expect(within(tile(CRITICAL_TILE)).getByText(String(RELEASE_CRITICAL))).toBeInTheDocument()
  })

  it('names a release that sits outside the branches and the page this view loaded', () => {
    const offPage = makeScan(
      { id: OFF_PAGE_SCAN_ID, branch: RETIRED_BRANCH, created_at: RELEASED_AT, is_release: true },
      { critical: OFF_PAGE_CRITICAL },
    )
    renderOverview(
      [head],
      [MAIN_BRANCH],
      releaseList({ branch: RETIRED_BRANCH, analysis_scan_id: OFF_PAGE_SCAN_ID }),
      [offPage],
    )

    expect(screen.getByLabelText(`Release ${RELEASE_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))

    expect(within(tile(CRITICAL_TILE)).getByText(String(OFF_PAGE_CRITICAL))).toBeInTheDocument()
  })
})
