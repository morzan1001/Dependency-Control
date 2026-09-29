import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { toast } from 'sonner'

import ScanDetails from '../ScanDetails'

const mockUseScan = vi.fn()
const mockMutate = vi.fn()
const ALREADY_UNDER_WAY = 'A re-scan of this scan is already under way.'
const RESCAN_BUTTON = { name: /trigger re-scan/i }

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

vi.mock('@/hooks/queries/use-scans', () => ({
  useScan: (...args: unknown[]) => mockUseScan(...args),
  useScanHistory: () => ({ data: undefined }),
  useTriggerRescan: () => ({ mutate: mockMutate, isPending: false }),
  useScanResults: () => ({ data: [], isLoading: false }),
  useScanSboms: () => ({ data: [], isLoading: false }),
  useScanStats: () => ({ data: undefined }),
}))

vi.mock('@/hooks/queries/use-projects', () => ({
  useProject: () => ({ data: { id: 'p1', name: 'Proj', active_analyzers: [] }, isLoading: false }),
}))

vi.mock('@/components/findings/FindingsTable', () => ({ FindingsTable: () => null }))
vi.mock('@/components/findings/WaivedFindingsSection', () => ({ WaivedFindingsSection: () => null }))
vi.mock('@/components/scans/MarkReleaseButton', () => ({ MarkReleaseButton: () => null }))
vi.mock('@/components/scans/ScanReleaseControl', () => ({ ScanReleaseControl: () => null }))

function scan(status: string) {
  return {
    id: 's1', project_id: 'p1', branch: 'main', status, created_at: '2026-09-01T00:00:00Z',
    sbom_refs: [{ type: 'gridfs_reference', gridfs_id: 'g1' }],
  }
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/projects/p1/scans/s1']}>
      <Routes>
        <Route path="/projects/:projectId/scans/:scanId" element={<ScanDetails />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(cleanup)

describe('ScanDetails re-scan button', () => {
  it('tells the user why the server refused the re-scan', () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
    mockMutate.mockImplementation((_vars, options: { onError: (error: unknown) => void }) =>
      options.onError({ response: { status: 409, data: { detail: ALREADY_UNDER_WAY } } }),
    )

    renderPage()
    fireEvent.click(screen.getByRole('button', RESCAN_BUTTON))

    expect(toast.error).toHaveBeenCalledWith(expect.any(String), { description: ALREADY_UNDER_WAY })
  })

  it.each(['pending', 'processing'])('cannot be clicked while the scan is %s', (status) => {
    mockUseScan.mockReturnValue({ data: scan(status), isLoading: false })

    renderPage()

    expect(screen.getByRole('button', RESCAN_BUTTON)).toBeDisabled()
  })

  it('can be clicked once the scan is analysed', () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })

    renderPage()

    expect(screen.getByRole('button', RESCAN_BUTTON)).toBeEnabled()
  })
})
