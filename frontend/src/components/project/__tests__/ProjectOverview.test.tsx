import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'

import { ProjectOverview } from '../ProjectOverview'
import type { EnhancedStats, ScanWithReleases } from '@/types/scan'

const PROJECT_ID = 'p1'
const MAIN_BRANCH = 'main'

const mockUseProjectScans = vi.fn()
const mockUseScanResults = vi.fn()
const mockUseProjectWaivers = vi.fn()

vi.mock('@/hooks/queries/use-scans', () => ({
  useProjectScans: (...args: unknown[]) => mockUseProjectScans(...args),
  useScanResults: (...args: unknown[]) => mockUseScanResults(...args),
}))

vi.mock('@/hooks/queries/use-waivers', () => ({
  useProjectWaivers: (...args: unknown[]) => mockUseProjectWaivers(...args),
}))

vi.mock('react-router-dom', () => ({
  useNavigate: () => vi.fn(),
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

function renderOverview(scans: ScanWithReleases[], selectedBranches: string[] = [MAIN_BRANCH]) {
  mockUseProjectScans.mockReturnValue({ data: scans, isLoading: false })
  mockUseScanResults.mockReturnValue({ data: [] })
  mockUseProjectWaivers.mockReturnValue({ data: undefined })
  return render(<ProjectOverview projectId={PROJECT_ID} selectedBranches={selectedBranches} />)
}

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

describe('ProjectOverview - release tile', () => {
  const PRODUCTION = 'production'
  const RELEASE_VERSION = 'v1.2.3'
  const ROLLED_BACK_VERSION = 'rolled-back'
  const RELEASED_AT = '2026-08-01T00:00:00Z'
  const ROLLED_BACK_AT = '2026-08-20T00:00:00Z'
  const RETIRED_BRANCH = 'release-1.0'
  const HEAD_CRITICAL = 9
  const HEAD_HIGH = 9
  const RELEASE_CRITICAL = 2
  const RELEASE_HIGH = 3
  const RESCANNED_CRITICAL = 1
  const CRITICAL_TILE = 'Critical Issues'
  const HIGH_TILE = 'High Issues'
  const SHOW_RELEASE_BUTTON = 'Show release numbers'
  const SHOW_HEAD_BUTTON = 'Show HEAD numbers'
  const NO_RELEASE_TEXT = 'No release marked'
  const GENERIC_RELEASE_LABEL = 'Release'

  const head = makeScan(
    { id: 's-head', created_at: '2026-09-01T00:00:00Z' },
    { critical: HEAD_CRITICAL, high: HEAD_HIGH },
  )
  const release = makeScan(
    {
      id: 's-release',
      created_at: RELEASED_AT,
      is_release: true,
      releases: [{ environment: PRODUCTION, version: RELEASE_VERSION, released_at: RELEASED_AT }],
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
    renderOverview([head, release])

    expect(screen.getByLabelText(`Release ${RELEASE_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()
  })

  it('says so when there is no release', () => {
    renderOverview([head])

    expect(screen.getByText(NO_RELEASE_TEXT)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: SHOW_RELEASE_BUTTON })).not.toBeInTheDocument()
  })

  it('shows HEAD numbers until the switch is used', () => {
    renderOverview([head, release])

    expect(within(tile(CRITICAL_TILE)).getByText(String(HEAD_CRITICAL))).toBeInTheDocument()
    expect(within(tile(HIGH_TILE)).getByText(String(HEAD_HIGH))).toBeInTheDocument()
  })

  it('switches the headline numbers to the release', () => {
    renderOverview([head, release])

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))

    expect(within(tile(CRITICAL_TILE)).getByText(String(RELEASE_CRITICAL))).toBeInTheDocument()
    expect(within(tile(HIGH_TILE)).getByText(String(RELEASE_HIGH))).toBeInTheDocument()
    expect(screen.getByRole('button', { name: SHOW_HEAD_BUTTON })).toBeInTheDocument()
  })

  it('says the switched numbers describe the release, not the branch head', () => {
    renderOverview([head, release])

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))

    expect(screen.getAllByText(`Release on ${MAIN_BRANCH} — click to view findings`).length).toBeGreaterThan(0)
    expect(screen.queryByText(`Branch ${MAIN_BRANCH} — click to view findings`)).not.toBeInTheDocument()
  })

  it('reads the release rescan numbers, not the stale release scan', () => {
    const rescanned = makeScan(
      {
        id: 's-release-rescanned',
        created_at: RELEASED_AT,
        is_release: true,
        releases: [{ environment: PRODUCTION, version: RELEASE_VERSION, released_at: RELEASED_AT }],
        latest_run: {
          scan_id: 's-release-rescan',
          status: 'completed',
          findings_count: RESCANNED_CRITICAL,
          stats: { critical: RESCANNED_CRITICAL, high: 0 },
        },
      },
      { critical: RELEASE_CRITICAL, high: RELEASE_HIGH },
    )
    renderOverview([head, rescanned])

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))

    expect(within(tile(CRITICAL_TILE)).getByText(String(RESCANNED_CRITICAL))).toBeInTheDocument()
  })

  it('keeps the release numbers while its rescan is still queued', () => {
    const rescanQueued = makeScan(
      {
        id: 's-release-queued',
        created_at: RELEASED_AT,
        is_release: true,
        releases: [{ environment: PRODUCTION, version: RELEASE_VERSION, released_at: RELEASED_AT }],
        // A queued rescan has analysed nothing yet, so its summary carries no stats.
        latest_run: { scan_id: 's-release-rescan', status: 'pending' },
      },
      { critical: RELEASE_CRITICAL, high: RELEASE_HIGH },
    )
    renderOverview([head, rescanQueued])

    fireEvent.click(screen.getByRole('button', { name: SHOW_RELEASE_BUTTON }))

    expect(within(tile(CRITICAL_TILE)).getByText(String(RELEASE_CRITICAL))).toBeInTheDocument()
  })

  it('picks the newest release by released_at, not by created_at', () => {
    const rolledBackTo = makeScan(
      {
        id: 's-old-build',
        created_at: '2026-07-01T00:00:00Z',
        is_release: true,
        releases: [{ environment: PRODUCTION, version: ROLLED_BACK_VERSION, released_at: ROLLED_BACK_AT }],
      },
      { critical: 1, high: 1 },
    )
    renderOverview([head, release, rolledBackTo])

    expect(screen.getByLabelText(`Release ${ROLLED_BACK_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()
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

  it('leaves out a release on a branch this view does not cover', () => {
    const retired = makeScan(
      {
        id: 's-retired',
        branch: RETIRED_BRANCH,
        created_at: RELEASED_AT,
        is_release: true,
        releases: [{ environment: PRODUCTION, version: RELEASE_VERSION, released_at: RELEASED_AT }],
      },
      { critical: RELEASE_CRITICAL, high: RELEASE_HIGH },
    )
    renderOverview([head, retired])

    expect(screen.getByText(NO_RELEASE_TEXT)).toBeInTheDocument()
  })
})
