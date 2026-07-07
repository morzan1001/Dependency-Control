import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'

import { ProjectOverview } from '../ProjectOverview'
import type { Scan } from '@/types/scan'

// --- Mocks -----------------------------------------------------------------

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

function makeScan(overrides: Partial<Scan>, stats: Record<string, unknown>): Scan {
  return {
    id: 'scan-1',
    branch: 'main',
    status: 'completed',
    is_rescan: false,
    created_at: '2026-07-01T00:00:00Z',
    stats,
    ...overrides,
  } as unknown as Scan
}

function renderOverview(scans: Scan[]) {
  mockUseProjectScans.mockReturnValue({ data: scans, isLoading: false })
  mockUseScanResults.mockReturnValue({ data: [] })
  mockUseProjectWaivers.mockReturnValue({ data: undefined })
  return render(<ProjectOverview projectId="p1" selectedBranches={['main']} />)
}

describe('ProjectOverview - ThreatIntelligenceDashboard gating', () => {
  it('renders the dashboard when reachability analysis exists with zero KEV/high-EPSS', () => {
    // Reproduces the bug: a scan with reachability data but no KEV / high-EPSS vulns.
    // Canonical fields analyzed_count / unreachable_count are populated by the accumulator;
    // the legacy total_analyzed / reachable fields are never emitted by the backend.
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
