import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ProjectScans } from '../ProjectScans'
import { DEFAULT_PAGE_SIZE } from '@/lib/constants'
import type { LatestProjectRelease } from '@/hooks/queries/use-releases'
import type { ScanWithReleases } from '@/types/scan'

const PRODUCTION = 'production'
const STAGING = 'staging'
const RELEASE_VERSION = 'v1.2.3'
const STAGING_VERSION = 'v1.3.0-rc1'
const RELEASED_AT = '2026-07-01T00:00:00Z'
const RELEASES_ONLY_BUTTON = 'Releases only'

const mockUseProjectScans = vi.fn()
const mockUseProjectBranches = vi.fn()
const mockUseLatestProjectRelease = vi.fn()

vi.mock('@/hooks/queries/use-scans', () => ({
  useProjectScans: (...args: unknown[]) => mockUseProjectScans(...args),
}))

vi.mock('@/hooks/queries/use-projects', () => ({
  useProjectBranches: (...args: unknown[]) => mockUseProjectBranches(...args),
}))

vi.mock('@/hooks/queries/use-releases', () => ({
  useLatestProjectRelease: (...args: unknown[]) => mockUseLatestProjectRelease(...args),
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

// Annotated, not inferred: an inferred fixture drops a field from the hook's type silently.
const HAS_RELEASES: LatestProjectRelease = { latestRelease: undefined, hasReleases: true, isLoading: false }
const NO_RELEASES: LatestProjectRelease = { latestRelease: undefined, hasReleases: false, isLoading: false }

function renderScans(scans: ScanWithReleases[], releases: LatestProjectRelease = HAS_RELEASES) {
  mockUseProjectScans.mockReturnValue({
    data: scans,
    isLoading: false,
    isPlaceholderData: false,
  })
  mockUseProjectBranches.mockReturnValue({ data: [] })
  mockUseLatestProjectRelease.mockReturnValue(releases)
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

  it('offers no Delta on a scan whose run has delivered no numbers', () => {
    const failed = makeScan({ id: 'main-failed', status: 'failed', created_at: '2026-07-03T00:00:00Z' })
    const pending = makeScan({ id: 'main-pending', status: 'pending', created_at: '2026-07-02T00:00:00Z' })
    const done = makeScan({ id: 'main-done', created_at: '2026-07-01T00:00:00Z' })

    renderScans([failed, pending, done])

    expect(screen.queryByRole('button', { name: 'Delta' })).not.toBeInTheDocument()
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
      // A queued rescan has no stats yet, and the lineage pointer moves only once a rescan delivers.
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

  it('says a second rescan is running while the lineage still points at the one that delivered', () => {
    renderScans([
      makeScan({
        id: 'main-1',
        latest_rescan_id: 'main-1-earlier-rescan',
        latest_run: { scan_id: RESCAN_ID, status: 'pending' },
      }),
    ])

    expect(screen.getByText(NOTE_IN_FLIGHT)).toBeInTheDocument()
    expect(screen.queryByText(NOTE_DELIVERED)).not.toBeInTheDocument()
  })

  it('adds no note while the latest run is the analysis of the scan itself', () => {
    renderScans([makeScan({ id: 'main-1', latest_run: { scan_id: 'main-1', status: 'completed' } })])

    expect(screen.queryByText(NOTE_IN_FLIGHT)).not.toBeInTheDocument()
    expect(screen.queryByText(NOTE_DELIVERED)).not.toBeInTheDocument()
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

  it('renders no badge for a release flag no release record backs', () => {
    renderScans([makeScan({ id: 'rel', is_release: true })])

    expect(screen.queryByLabelText(/^Release/)).not.toBeInTheDocument()
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

describe('ProjectScans - the release filter on a project that does not release', () => {
  it('offers no release filter', () => {
    renderScans([makeScan({ id: 'plain' })], NO_RELEASES)

    expect(screen.queryByRole('button', { name: RELEASES_ONLY_BUTTON })).not.toBeInTheDocument()
  })

  it('keeps the filter while it is engaged, so a withdrawal cannot strand the user in it', () => {
    const { rerender } = renderScans([makeScan({ id: 'rel', is_release: true })])

    fireEvent.click(screen.getByRole('button', { name: RELEASES_ONLY_BUTTON }))
    mockUseLatestProjectRelease.mockReturnValue(NO_RELEASES)
    rerender(<ProjectScans projectId="p1" />)

    expect(screen.getByRole('button', { name: RELEASES_ONLY_BUTTON })).toBeInTheDocument()
  })

  it('lets the filter go once the user switches it off', () => {
    const { rerender } = renderScans([makeScan({ id: 'rel', is_release: true })])

    fireEvent.click(screen.getByRole('button', { name: RELEASES_ONLY_BUTTON }))
    mockUseLatestProjectRelease.mockReturnValue(NO_RELEASES)
    rerender(<ProjectScans projectId="p1" />)
    fireEvent.click(screen.getByRole('button', { name: RELEASES_ONLY_BUTTON }))

    expect(screen.queryByRole('button', { name: RELEASES_ONLY_BUTTON })).not.toBeInTheDocument()
  })
})

describe('ProjectScans - source links', () => {
  const GITLAB = 'https://gitlab.example.com/acme/widget'
  const COMMIT = 'abcdef1234567890abcdef1234567890abcdef12'

  it('links pipeline, branch and commit to the SCM without opening the scan', () => {
    renderScans([makeScan({
      project_url: GITLAB, pipeline_id: 9001, pipeline_iid: 42, branch: 'feature/x', commit_hash: COMMIT,
    })])

    const pipeline = screen.getByRole('link', { name: '#42' })
    const branch = screen.getByRole('link', { name: 'feature/x' })
    const commit = screen.getByRole('link', { name: 'abcdef1' })
    expect(pipeline).toHaveAttribute('href', `${GITLAB}/-/pipelines/9001`)
    expect(branch).toHaveAttribute('href', `${GITLAB}/-/tree/feature/x`)
    expect(commit).toHaveAttribute('href', `${GITLAB}/-/commit/${COMMIT}`)
    expect(commit).toHaveAttribute('title', COMMIT)
    for (const link of [pipeline, branch, commit]) {
      expect(link).toHaveAttribute('target', '_blank')
      expect(link).toHaveAttribute('rel', 'noopener noreferrer')
      fireEvent.click(link)
    }
    expect(mockNavigate).not.toHaveBeenCalled()
  })

  it('shows the values as plain text when the SCM is unknown', () => {
    renderScans([makeScan({ pipeline_iid: 42, branch: 'feature/x', commit_hash: COMMIT })])

    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.getByText('#42')).toBeInTheDocument()
    expect(screen.getByText('feature/x')).toBeInTheDocument()
    expect(screen.getByText('abcdef1')).toBeInTheDocument()
  })

  it('says N/A for a scan without pipeline or commit', () => {
    renderScans([makeScan({ project_url: GITLAB })])

    expect(screen.getAllByText('N/A')).toHaveLength(2)
  })
})


describe('ProjectScans - sorting', () => {
  const lastSort = () => {
    const filters = mockUseProjectScans.mock.calls[mockUseProjectScans.mock.calls.length - 1][1]
    return [filters.sortBy, filters.sortOrder]
  }

  it('lists the newest pipelines first, then sorts a text column ascending first and flips it', () => {
    renderScans([makeScan({ id: 's1' })])
    expect(lastSort()).toEqual(['created_at', 'desc'])

    fireEvent.click(screen.getByRole('columnheader', { name: 'Branch' }))
    expect(lastSort()).toEqual(['branch', 'asc'])

    fireEvent.click(screen.getByRole('columnheader', { name: 'Branch' }))
    expect(lastSort()).toEqual(['branch', 'desc'])
  })

  it.each([
    ['Status', 'status', 'asc'],
    ['Findings', 'findings_count', 'desc'],
  ])('sorts the %s column by %s, %s first', (name, column, order) => {
    renderScans([makeScan({ id: 's1' })])

    fireEvent.click(screen.getByRole('columnheader', { name }))

    expect(lastSort()).toEqual([column, order])
  })

  it('returns to the first page when a column is sorted, like the other paged tables', () => {
    renderScans(Array.from({ length: DEFAULT_PAGE_SIZE }, (_, i) => makeScan({ id: `s${i}` })))
    const lastPage = () => mockUseProjectScans.mock.calls[mockUseProjectScans.mock.calls.length - 1][1].page
    fireEvent.click(screen.getByRole('button', { name: /Next/ }))
    expect(lastPage()).toBe(2)

    fireEvent.click(screen.getByRole('columnheader', { name: 'Branch' }))

    expect(lastPage()).toBe(1)
    expect(lastSort()).toEqual(['branch', 'asc'])
  })
})

describe('ProjectScans - findings counts', () => {
  it('writes the high count in the severity colour beside the critical count', () => {
    renderScans([makeScan({ id: 'risky', stats: { critical: 2, high: 13, medium: 0, low: 0 } })])

    expect(screen.getByText('13')).toHaveClass('text-severity-high')
  })
})

describe('ProjectScans - long branch names', () => {
  it('breaks a long branch name anywhere and keeps the row icons whole beside it', () => {
    const branch = 'feature/checkout-redesign-with-a-rather-long-branch-name'
    renderScans([makeScan({ id: 'long', branch, commit_hash: '6722380abc' })])

    const row = screen.getByText(branch).closest('tr')!
    expect(screen.getByText(branch)).toHaveClass('wrap-anywhere')
    for (const icon of ['lucide-calendar', 'lucide-git-branch', 'lucide-git-commit-horizontal']) {
      expect(row.querySelector(`svg.${icon}`)).toHaveClass('shrink-0')
    }
  })
})

describe('ProjectScans - on a narrow screen', () => {
  it("stacks its filters under the title on a phone, like the waiver list's header, and wraps them", () => {
    renderScans([makeScan({})])

    const header = screen.getByRole('heading', { name: 'Pipelines' }).parentElement?.parentElement
    expect(header).toHaveClass('flex-col', 'sm:flex-row', 'sm:items-center', 'sm:justify-between')
    const branchSelect = screen.getByRole('combobox')
    expect(branchSelect).toHaveClass('w-full', 'sm:w-[200px]')
    expect(branchSelect.parentElement).toHaveClass('flex-wrap')
  })

  it('keeps the columns at their widths and scrolls the table sideways below lg, so a desktop still shows the Delta column', () => {
    renderScans([makeScan({})])

    const table = screen.getByRole('table')
    expect(table).toHaveClass('min-w-[1090px]', 'lg:min-w-0')
    expect(table.parentElement).toHaveClass('overflow-auto')
  })

  it("names an empty list under the table, where a phone shows it, instead of in a row centred on the table's 1090px", async () => {
    renderScans([])

    expect((await screen.findByText('No scans found.')).closest('table')).toBeNull()
  })
})
