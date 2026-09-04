import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ProjectScans } from '../ProjectScans'
import type { ScanWithReleases } from '@/types/scan'

const PRODUCTION = 'production'
const STAGING = 'staging'
const RELEASE_VERSION = 'v1.2.3'
const STAGING_VERSION = 'v1.3.0-rc1'
const RELEASED_AT = '2026-07-01T00:00:00Z'
const RELEASES_ONLY_BUTTON = 'Releases only'
const GENERIC_RELEASE_LABEL = 'Release'

const mockUseProjectScans = vi.fn()
const mockUseProjectBranches = vi.fn()

vi.mock('@/hooks/queries/use-scans', () => ({
  useProjectScans: (...args: unknown[]) => mockUseProjectScans(...args),
}))

vi.mock('@/hooks/queries/use-projects', () => ({
  useProjectBranches: (...args: unknown[]) => mockUseProjectBranches(...args),
}))

const mockNavigate = vi.fn()

vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}))

function makeScan(overrides: Partial<ScanWithReleases>): ScanWithReleases {
  return {
    id: 'scan-x',
    project_id: 'p1',
    branch: 'main',
    status: 'completed',
    is_release: false,
    releases: [],
    created_at: '2026-07-01T00:00:00Z',
    stats: { critical: 0, high: 0, medium: 0, low: 0 },
    ...overrides,
  }
}

function renderScans(scans: ScanWithReleases[]) {
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
    // Branches interleaved in created_at desc order; adjacent-row pairing would wrongly cross branches.
    const newestMain = makeScan({ id: 'main-new', branch: 'main', created_at: '2026-07-03T00:00:00Z' })
    const feature = makeScan({ id: 'feat-1', branch: 'feature', created_at: '2026-07-02T00:00:00Z' })
    const olderMain = makeScan({ id: 'main-old', branch: 'main', created_at: '2026-07-01T00:00:00Z' })

    renderScans([newestMain, feature, olderMain])

    const deltaButtons = screen.getAllByRole('button', { name: 'Delta' })
    // Only the newest main scan has an earlier same-branch completed partner.
    expect(deltaButtons).toHaveLength(1)

    fireEvent.click(deltaButtons[0])

    expect(mockNavigate).toHaveBeenCalledWith('/projects/p1/delta?from=main-old&to=main-new')
  })

  it('does not offer a Delta when the only same-branch neighbor is a different branch', () => {
    const main = makeScan({ id: 'main-1', branch: 'main', created_at: '2026-07-02T00:00:00Z' })
    const feature = makeScan({ id: 'feat-1', branch: 'feature', created_at: '2026-07-01T00:00:00Z' })

    renderScans([main, feature])

    expect(screen.queryByRole('button', { name: 'Delta' })).not.toBeInTheDocument()
  })

  it('treats a completed_with_errors scan as a valid delta partner', () => {
    const newest = makeScan({ id: 'main-new', created_at: '2026-07-03T00:00:00Z' })
    const partial = makeScan({
      id: 'main-partial',
      status: 'completed_with_errors',
      created_at: '2026-07-01T00:00:00Z',
    })

    renderScans([newest, partial])

    const deltaButtons = screen.getAllByRole('button', { name: 'Delta' })
    expect(deltaButtons).toHaveLength(1)

    fireEvent.click(deltaButtons[0])

    expect(mockNavigate).toHaveBeenCalledWith('/projects/p1/delta?from=main-partial&to=main-new')
  })

  it('renders the completed_with_errors badge in the pipelines table', () => {
    renderScans([makeScan({ id: 'main-partial', status: 'completed_with_errors' })])

    expect(screen.getByText('completed with errors')).toBeInTheDocument()
  })
})

describe('ProjectScans - a scan whose rescan is still queued', () => {
  const OWN_CRITICAL = 4
  const RESCAN_ID = 'main-1-rescan'
  const NO_HIGH_RISKS = 'No high risks'
  const NOTE_DELIVERED = 'Updated via re-scan'
  const NOTE_IN_FLIGHT = 'Re-scan in progress'
  const NOTE_FAILED = 'Re-scan failed'

  function queuedRescan(): ScanWithReleases {
    return makeScan({
      id: 'main-1',
      stats: { critical: OWN_CRITICAL, high: 0, medium: 0, low: 0 },
      latest_rescan_id: RESCAN_ID,
      // A queued rescan has analysed nothing yet, so its summary carries no stats.
      latest_run: { scan_id: RESCAN_ID, status: 'pending' },
    })
  }

  it('keeps the findings the scan itself reports instead of reading the queue as clean', () => {
    renderScans([queuedRescan()])

    expect(screen.getByText(String(OWN_CRITICAL))).toBeInTheDocument()
    expect(screen.queryByText(NO_HIGH_RISKS)).not.toBeInTheDocument()
  })

  it('shows the status of the run those findings came from', () => {
    renderScans([queuedRescan()])

    expect(screen.getByText('completed')).toBeInTheDocument()
    expect(screen.queryByText('pending')).not.toBeInTheDocument()
  })

  it('deltas against the run it counted, not the rescan that has analysed nothing', () => {
    const newer = makeScan({ id: 'main-2', created_at: '2026-07-05T00:00:00Z' })

    renderScans([newer, queuedRescan()])

    fireEvent.click(screen.getByRole('button', { name: 'Delta' }))

    expect(mockNavigate).toHaveBeenCalledWith('/projects/p1/delta?from=main-1&to=main-2')
  })

  it('deltas against a finished rescan, which is what the row counted', () => {
    const rescanned = makeScan({
      id: 'main-1',
      latest_rescan_id: RESCAN_ID,
      latest_run: { scan_id: RESCAN_ID, status: 'completed', stats: { critical: 0 } },
    })
    const newer = makeScan({ id: 'main-2', created_at: '2026-07-05T00:00:00Z' })

    renderScans([newer, rescanned])

    fireEvent.click(screen.getByRole('button', { name: 'Delta' }))

    expect(mockNavigate).toHaveBeenCalledWith(`/projects/p1/delta?from=${RESCAN_ID}&to=main-2`)
  })

  it('says the rescan is still running instead of claiming the row was updated by it', () => {
    renderScans([queuedRescan()])

    expect(screen.getByText(NOTE_IN_FLIGHT)).toBeInTheDocument()
    expect(screen.queryByText(NOTE_DELIVERED)).not.toBeInTheDocument()
  })

  it('says the row was updated once the rescan has delivered its results', () => {
    renderScans([
      makeScan({
        id: 'main-1',
        latest_rescan_id: RESCAN_ID,
        latest_run: { scan_id: RESCAN_ID, status: 'completed', stats: { critical: 0 } },
      }),
    ])

    expect(screen.getByText(NOTE_DELIVERED)).toBeInTheDocument()
    expect(screen.queryByText(NOTE_IN_FLIGHT)).not.toBeInTheDocument()
  })

  it('names a failed rescan as failed rather than as still running', () => {
    renderScans([
      makeScan({
        id: 'main-1',
        latest_rescan_id: RESCAN_ID,
        latest_run: { scan_id: RESCAN_ID, status: 'failed', stats: {} },
      }),
    ])

    expect(screen.getByText(NOTE_FAILED)).toBeInTheDocument()
    expect(screen.queryByText(NOTE_IN_FLIGHT)).not.toBeInTheDocument()
  })
})

describe('ProjectScans - release', () => {
  it('renders the release badge with its environment', () => {
    renderScans([
      makeScan({
        id: 'rel',
        is_release: true,
        releases: [{ environment: PRODUCTION, version: RELEASE_VERSION, released_at: RELEASED_AT }],
      }),
    ])

    expect(screen.getByLabelText(`Release ${RELEASE_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()
  })

  it('renders one badge per environment the scan runs in', () => {
    renderScans([
      makeScan({
        id: 'rel',
        is_release: true,
        releases: [
          { environment: STAGING, version: STAGING_VERSION, released_at: RELEASED_AT },
          { environment: PRODUCTION, version: RELEASE_VERSION, released_at: RELEASED_AT },
        ],
      }),
    ])

    expect(screen.getByLabelText(`Release ${STAGING_VERSION} in ${STAGING}`)).toBeInTheDocument()
    expect(screen.getByLabelText(`Release ${RELEASE_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()
  })

  it('still marks a scan whose release record has not landed yet', () => {
    renderScans([makeScan({ id: 'rel', is_release: true })])

    expect(screen.getByLabelText(GENERIC_RELEASE_LABEL)).toBeInTheDocument()
  })

  it('renders no badge for a plain scan', () => {
    renderScans([makeScan({ id: 'plain' })])

    expect(screen.queryByLabelText(/^Release/)).not.toBeInTheDocument()
  })

  it('asks the backend for releases only once the filter is on', () => {
    renderScans([makeScan({ id: 'plain' })])

    expect(mockUseProjectScans.mock.calls[0][1].isRelease).toBeUndefined()

    fireEvent.click(screen.getByRole('button', { name: RELEASES_ONLY_BUTTON }))

    const lastCall = mockUseProjectScans.mock.calls[mockUseProjectScans.mock.calls.length - 1]
    expect(lastCall[1].isRelease).toBe(true)
  })

  it('stops excluding deleted branches while the release filter is on', () => {
    renderScans([makeScan({ id: 'plain' })])

    expect(mockUseProjectScans.mock.calls[0][1].excludeDeletedBranches).toBe(true)

    fireEvent.click(screen.getByRole('button', { name: RELEASES_ONLY_BUTTON }))

    const lastCall = mockUseProjectScans.mock.calls[mockUseProjectScans.mock.calls.length - 1]
    expect(lastCall[1].excludeDeletedBranches).toBe(false)
  })
})
