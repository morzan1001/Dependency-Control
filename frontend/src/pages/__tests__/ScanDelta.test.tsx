import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ScanDelta from '../ScanDelta'
import * as deltaApi from '@/api/scanDelta'
import * as scansApi from '@/api/scans'
import { releaseApi } from '@/api/releases'
import type { DeltaCategory, ScanDeltaResponse } from '@/types/scanDelta'
import type { ReleaseListResponse } from '@/types/release'
import type { ScanWithReleases } from '@/types/scan'

vi.mock('@/api/scanDelta')
vi.mock('@/api/scans')
vi.mock('@/api/releases')

const PROJECT_ID = 'p1'
const FROM_SCAN_ID = 'a'
const TO_SCAN_ID = 'b'
const RELEASE_SCAN_ID = 'rel-1'
const PRODUCTION = 'production'
const RELEASE_VERSION = 'v1'
const RELEASE_QUICK_PICK = `Latest ${PRODUCTION} release`
const COMPLETED = 'completed'
const FIRST_PAGE = 1
// The quick pick reads only the newest release, so the header asks for a single row.
const LATEST_RELEASE_LIMIT = 1
const NO_RELEASES = 0
const COVERABLE = 120
const ANALYSED = 118
const NOT_ANALYSED = 0
const FROM_WAIVED = 12
const TO_WAIVED = 9
const RISK_SCORE_WARNING = /only its risk scores are reachability-adjusted/i
const LAPSED_WAIVER_WARNING = /before treating an added finding as newly introduced/i

// Annotated, not inferred: an inferred fixture drops a field from the response type silently.
const emptyDelta = (
  category: DeltaCategory,
  overrides: Partial<ScanDeltaResponse> = {},
): ScanDeltaResponse => ({
  category, from_scan_id: FROM_SCAN_ID, to_scan_id: TO_SCAN_ID, project_id: PROJECT_ID,
  totals: { added: 2, removed: 1, unchanged: 5, changed: 0, by_severity: {}, by_type: {} },
  page: FIRST_PAGE, page_size: 50, total_pages: 1, items: [],
  from_waived_excluded: 0, to_waived_excluded: 0,
  ...overrides,
})

const scan = (id: string): ScanWithReleases => ({
  id, project_id: PROJECT_ID, branch: 'main', status: COMPLETED,
  created_at: '2026-08-10T12:00:00Z', commit_hash: `c-${id}`, is_release: false, releases: [],
})

const noReleases: ReleaseListResponse = {
  items: [], total: NO_RELEASES, page: FIRST_PAGE, size: LATEST_RELEASE_LIMIT,
}

const oneRelease: ReleaseListResponse = {
  items: [{
    scan_id: RELEASE_SCAN_ID, project_id: PROJECT_ID, environment: PRODUCTION, version: RELEASE_VERSION,
    commit_hash: `c-${RELEASE_SCAN_ID}`, branch: 'main', released_at: '2026-01-01T00:00:00Z',
    scan_status: COMPLETED, analysis_scan_id: RELEASE_SCAN_ID,
  }],
  total: 1, page: FIRST_PAGE, size: LATEST_RELEASE_LIMIT,
}

function renderPage(url = `/projects/${PROJECT_ID}/delta?from=${FROM_SCAN_ID}&to=${TO_SCAN_ID}`) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>
        <Routes>
          <Route path="/projects/:id/delta" element={<ScanDelta />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ScanDelta page', () => {
  afterEach(() => { cleanup(); vi.clearAllMocks() })

  it('loads the findings delta for the scan pair from the URL', async () => {
    vi.mocked(deltaApi.getScanDelta).mockResolvedValue(emptyDelta('findings'))
    vi.mocked(scansApi.scanApi.getOne).mockImplementation((id: string) => Promise.resolve(scan(id)))
    vi.mocked(releaseApi.list).mockResolvedValue(noReleases)

    renderPage()

    await waitFor(() => expect(deltaApi.getScanDelta).toHaveBeenCalled())
    const args = vi.mocked(deltaApi.getScanDelta).mock.calls[0][0]
    expect(args).toMatchObject({
      projectId: PROJECT_ID, fromScanId: FROM_SCAN_ID, toScanId: TO_SCAN_ID, category: 'findings',
    })
  })

  // The page rejects the pair before it renders the header, so nothing asks for a release here.
  it('shows an error card for an invalid scan pair', () => {
    renderPage(`/projects/${PROJECT_ID}/delta?from=${FROM_SCAN_ID}&to=${FROM_SCAN_ID}`)
    expect(screen.getByText(/invalid scan comparison/i)).toBeInTheDocument()
  })

  it('carries the per-side labels from the response up to the header', async () => {
    vi.mocked(deltaApi.getScanDelta).mockResolvedValue(
      emptyDelta('findings', {
        from_reachability: { coverable_count: COVERABLE, analyzed_count: NOT_ANALYSED },
        to_reachability: { coverable_count: COVERABLE, analyzed_count: ANALYSED },
        from_waived_excluded: FROM_WAIVED,
        to_waived_excluded: TO_WAIVED,
      }),
    )
    vi.mocked(scansApi.scanApi.getOne).mockImplementation((id: string) => Promise.resolve(scan(id)))
    vi.mocked(releaseApi.list).mockResolvedValue(noReleases)

    renderPage()

    expect(await screen.findByText(new RegExp(`${FROM_WAIVED} waived hidden`))).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`${TO_WAIVED} waived hidden`))).toBeInTheDocument()
    expect(screen.getByText(RISK_SCORE_WARNING)).toBeInTheDocument()
    expect(screen.getByText(LAPSED_WAIVER_WARNING)).toBeInTheDocument()
  })

  it('re-anchors the comparison on the latest release', async () => {
    vi.mocked(deltaApi.getScanDelta).mockResolvedValue(emptyDelta('findings'))
    vi.mocked(scansApi.scanApi.getOne).mockImplementation((id: string) => Promise.resolve(scan(id)))
    vi.mocked(releaseApi.list).mockResolvedValue(oneRelease)

    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: RELEASE_QUICK_PICK }))

    await waitFor(() =>
      expect(vi.mocked(deltaApi.getScanDelta).mock.lastCall?.[0]).toMatchObject({
        fromScanId: RELEASE_SCAN_ID,
        toScanId: TO_SCAN_ID,
      }),
    )
  })
})
