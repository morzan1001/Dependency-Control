// Force a non-UTC timezone so the UTC-vs-local date-parsing bug is observable.
process.env.TZ = 'America/New_York'

import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import ArchivesPage from '../Archives'
import type { AdminArchiveListItem, AdminArchiveListResponse, ArchiveFilters } from '@/types/archive'

// --- Mocks -----------------------------------------------------------------

const mockUseAdminArchives = vi.fn()

vi.mock('@/hooks/queries/use-archives', () => ({
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
    // 1 TiB previously overflowed the sizes array (ends at GB) -> "1.0 undefined".
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

describe('ArchivesPage - date filters', () => {
  it('builds date_from with the same local-time convention as date_to', () => {
    renderPage()

    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-07-01' } })
    fireEvent.change(screen.getByLabelText('To'), { target: { value: '2026-07-01' } })

    const lastCall = mockUseAdminArchives.mock.calls.at(-1)
    const filters = lastCall?.[2] as (ArchiveFilters & { project_id?: string }) | undefined

    // Both bounds must be parsed as LOCAL time; date_from as UTC midnight
    // (the old bug) diverges from this in a non-UTC timezone.
    expect(filters?.date_from).toBe(new Date('2026-07-01T00:00:00').toISOString())
    expect(filters?.date_to).toBe(new Date('2026-07-01T23:59:59').toISOString())
  })
})
