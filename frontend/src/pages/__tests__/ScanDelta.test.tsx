import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ScanDelta from '../ScanDelta'
import * as deltaApi from '@/api/scanDelta'
import * as scansApi from '@/api/scans'

vi.mock('@/api/scanDelta')
vi.mock('@/api/scans')

const emptyDelta = (category: string) => ({
  category, from_scan_id: 'a', to_scan_id: 'b', project_id: 'p1',
  totals: { added: 2, removed: 1, unchanged: 5, changed: 0, by_severity: {}, by_type: {} },
  page: 1, page_size: 50, total_pages: 1, items: [],
})

const scan = (id: string) => ({
  id, project_id: 'p1', branch: 'main', status: 'completed',
  created_at: '2026-08-10T12:00:00Z', commit_hash: `c-${id}`,
})

function renderPage(url = '/projects/p1/delta?from=a&to=b') {
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

    renderPage()

    await waitFor(() => expect(deltaApi.getScanDelta).toHaveBeenCalled())
    const args = vi.mocked(deltaApi.getScanDelta).mock.calls[0][0]
    expect(args).toMatchObject({ projectId: 'p1', fromScanId: 'a', toScanId: 'b', category: 'findings' })
  })

  it('shows an error card for an invalid scan pair', () => {
    renderPage('/projects/p1/delta?from=a&to=a')
    expect(screen.getByText(/invalid scan comparison/i)).toBeInTheDocument()
  })
})
