// Force a non-UTC timezone so date parsing is exercised in local time.
process.env.TZ = 'America/New_York'

import { act, render, screen, fireEvent, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import ArchivesPage from '../Archives'
import type { AdminArchiveListItem, AdminArchiveListResponse, ArchiveFilters } from '@/types/archive'
import { DEBOUNCE_DELAY_MS } from '@/lib/constants'

const mockUseAdminArchives = vi.fn()

vi.mock('@/hooks/queries/use-archives', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/queries/use-archives')>()),
  useAdminArchives: (...args: unknown[]) => mockUseAdminArchives(...args),
}))

function makeArchive(overrides: Partial<AdminArchiveListItem> = {}): AdminArchiveListItem {
  return {
    id: 'a1',
    scan_id: 's1',
    project_id: 'p1',
    project_name: 'Proj 1',
    branch: 'main',
    commit_hash: 'abcdef1234567890',
    scan_created_at: '2026-07-01T12:00:00Z',
    archived_at: '2026-07-02T12:00:00Z',
    compressed_size_bytes: 1024,
    findings_count: 0,
    critical_findings_count: 0,
    high_findings_count: 0,
    dependencies_count: 0,
    sbom_filenames: [],
    ...overrides,
  }
}

function makeResponse(items: AdminArchiveListItem[]): AdminArchiveListResponse {
  return { items, total: items.length, page: 1, size: 20, pages: 1 }
}

function renderPage() {
  return render(
    <MemoryRouter>
      <ArchivesPage />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  mockUseAdminArchives.mockReset()
  mockUseAdminArchives.mockReturnValue({ data: makeResponse([]), isLoading: false })
})

describe('ArchivesPage - formatBytes', () => {
  it('renders terabyte-scale sizes without an undefined unit', () => {
    const oneTiB = 1024 ** 4
    mockUseAdminArchives.mockReturnValue({
      data: makeResponse([makeArchive({ compressed_size_bytes: oneTiB })]),
      isLoading: false,
    })

    renderPage()

    expect(screen.getByText('1.0 TB')).toBeInTheDocument()
    expect(screen.queryByText(/undefined/)).not.toBeInTheDocument()
  })
})

describe('ArchivesPage rows', () => {
  it('summarises an archived scan with its project and archive time', () => {
    mockUseAdminArchives.mockReturnValue({
      data: makeResponse([makeArchive({
        branch: 'release/2.0', findings_count: 17, critical_findings_count: 2, high_findings_count: 5,
        dependencies_count: 321, sbom_filenames: ['sbom-a.json', 'sbom-b.json'], compressed_size_bytes: 2048,
      })]),
      isLoading: false,
    })

    renderPage()

    const row = screen.getByRole('row', { name: /release\/2\.0/ })
    expect(within(row).getByRole('link', { name: 'Proj 1' })).toHaveAttribute('href', '/projects/p1')
    for (const text of ['release/2.0', 'abcdef1', '17', '2 C', '5 H', '321', '2', '2.0 KB']) {
      expect(within(row).getByText(text)).toBeInTheDocument()
    }
    expect(within(row).getByText(new Date('2026-07-02T12:00:00Z').toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    }))).toBeInTheDocument()
  })

  it('tells an unfiltered empty list apart from a filtered one', () => {
    renderPage()
    expect(screen.getByText('Archives will appear here when data retention archiving is active.')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-07-01' } })
    expect(screen.getByText('Try adjusting your filters.')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(screen.getByLabelText('From')).toHaveValue('')
  })
})

describe('ArchivesPage pager', () => {
  it('names the archive total and asks for the next page', () => {
    mockUseAdminArchives.mockReturnValue({
      data: { items: [makeArchive()], total: 40, page: 1, size: 20, pages: 2 },
      isLoading: false,
    })

    renderPage()
    expect(screen.getByText('Page 1 of 2 (40 total)')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /next/i }))

    expect(mockUseAdminArchives).toHaveBeenLastCalledWith(2, 20, undefined)
  })
})

describe('ArchivesPage - date filters', () => {
  it('builds date_from with the same local-time convention as date_to', () => {
    renderPage()

    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-07-01' } })
    fireEvent.change(screen.getByLabelText('To'), { target: { value: '2026-07-01' } })

    const lastCall = mockUseAdminArchives.mock.calls[mockUseAdminArchives.mock.calls.length - 1]
    const filters = lastCall?.[2] as (ArchiveFilters & { project_id?: string }) | undefined

    expect(filters?.date_from).toBe(new Date('2026-07-01T00:00:00').toISOString())
    expect(filters?.date_to).toBe(new Date('2026-07-01T23:59:59').toISOString())
  })
})

describe('ArchivesPage branch filter', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('asks for a branch once the user stops typing, not once per keystroke', () => {
    vi.useFakeTimers()
    renderPage()
    const input = screen.getByLabelText('Branch')

    for (const value of ['m', 'ma', 'main']) fireEvent.change(input, { target: { value } })
    act(() => {
      vi.advanceTimersByTime(DEBOUNCE_DELAY_MS)
    })

    const requested = mockUseAdminArchives.mock.calls.map(([, , filters]) => (filters as ArchiveFilters | undefined)?.branch)
    expect(new Set(requested.filter(Boolean))).toEqual(new Set(['main']))
  })
})
