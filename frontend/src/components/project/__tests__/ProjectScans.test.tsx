import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ProjectScans } from '../ProjectScans'
import type { Scan } from '@/types/scan'

// --- Mocks -----------------------------------------------------------------

const mockUseProjectScans = vi.fn()
const mockUseProjectBranches = vi.fn()

vi.mock('@/hooks/queries/use-scans', () => ({
  useProjectScans: (...args: unknown[]) => mockUseProjectScans(...args),
}))

vi.mock('@/hooks/queries/use-projects', () => ({
  useProjectBranches: (...args: unknown[]) => mockUseProjectBranches(...args),
}))

vi.mock('react-router-dom', () => ({
  useNavigate: () => vi.fn(),
}))

// Expose the scan pair the Delta button hands to the modal.
vi.mock('@/components/scans/delta/ScanDeltaModal', () => ({
  ScanDeltaModal: ({
    fromScanId,
    toScanId,
  }: {
    fromScanId: string | null
    toScanId: string | null
  }) =>
    fromScanId && toScanId ? (
      <div data-testid="delta-modal" data-from={fromScanId} data-to={toScanId} />
    ) : null,
}))

function makeScan(overrides: Partial<Scan>): Scan {
  return {
    id: 'scan-x',
    project_id: 'p1',
    branch: 'main',
    status: 'completed',
    created_at: '2026-07-01T00:00:00Z',
    stats: { critical: 0, high: 0, medium: 0, low: 0 },
    ...overrides,
  } as unknown as Scan
}

function renderScans(scans: Scan[]) {
  mockUseProjectScans.mockReturnValue({
    data: scans,
    isLoading: false,
    isPlaceholderData: false,
  })
  mockUseProjectBranches.mockReturnValue({ data: [] })
  return render(<ProjectScans projectId="p1" />)
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('ProjectScans - Delta comparison partner', () => {
  it('compares against the previous completed scan of the SAME branch, not the adjacent row', () => {
    // API order (created_at desc) with interleaved branches. The adjacent-row
    // approach would pair the newest main scan with the feature scan below it.
    const newestMain = makeScan({ id: 'main-new', branch: 'main', created_at: '2026-07-03T00:00:00Z' })
    const feature = makeScan({ id: 'feat-1', branch: 'feature', created_at: '2026-07-02T00:00:00Z' })
    const olderMain = makeScan({ id: 'main-old', branch: 'main', created_at: '2026-07-01T00:00:00Z' })

    renderScans([newestMain, feature, olderMain])

    const deltaButtons = screen.getAllByRole('button', { name: 'Delta' })
    // Only the newest main scan has an earlier same-branch completed partner.
    expect(deltaButtons).toHaveLength(1)

    fireEvent.click(deltaButtons[0])

    const modal = screen.getByTestId('delta-modal')
    expect(modal).toHaveAttribute('data-from', 'main-old')
    expect(modal).toHaveAttribute('data-to', 'main-new')
  })

  it('does not offer a Delta when the only same-branch neighbor is a different branch', () => {
    const main = makeScan({ id: 'main-1', branch: 'main', created_at: '2026-07-02T00:00:00Z' })
    const feature = makeScan({ id: 'feat-1', branch: 'feature', created_at: '2026-07-01T00:00:00Z' })

    renderScans([main, feature])

    expect(screen.queryByRole('button', { name: 'Delta' })).not.toBeInTheDocument()
  })
})
