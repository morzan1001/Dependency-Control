// Force a non-UTC timezone so date parsing is exercised in local time.
process.env.TZ = 'America/New_York'

import { render, screen, fireEvent, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ProjectArchives } from '../ProjectArchives'
import { projectApi } from '@/api/projects'
import { downloadServerFile } from '@/lib/download'
import type { ArchiveFilters, ArchiveListItem, ArchiveListResponse } from '@/types/archive'

const mockUseProjectArchives = vi.fn()
const mockRestore = vi.fn()
const mockHasPermission = vi.fn()

vi.mock('@/hooks/queries/use-projects', () => ({
  useProjectArchives: (...args: unknown[]) => mockUseProjectArchives(...args),
  useArchiveBranches: () => ({ data: ['main'] }),
  useRestoreArchive: () => ({ mutate: mockRestore, isPending: false }),
}))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ hasPermission: mockHasPermission }) }))
vi.mock('@/api/projects', () => ({ projectApi: { downloadArchive: vi.fn() } }))
vi.mock('@/lib/download', () => ({ downloadServerFile: vi.fn() }))

const ARCHIVE: ArchiveListItem = {
  id: 'a1',
  scan_id: 's1',
  branch: 'release/2.0',
  commit_hash: 'abcdef1234567890',
  scan_created_at: '2026-07-01T12:00:00Z',
  archived_at: '2026-07-02T12:00:00Z',
  compressed_size_bytes: 2048,
  findings_count: 17,
  critical_findings_count: 2,
  high_findings_count: 5,
  dependencies_count: 321,
  sbom_filenames: ['sbom-a.json', 'sbom-b.json'],
}

function makeResponse(items: ArchiveListItem[]): ArchiveListResponse {
  return { items, total: items.length, page: 1, size: 20, pages: 1 }
}

beforeEach(() => {
  vi.clearAllMocks()
  mockUseProjectArchives.mockReset()
  mockUseProjectArchives.mockReturnValue({ data: makeResponse([]), isLoading: false })
  mockHasPermission.mockReturnValue(true)
})

describe('ProjectArchives rows', () => {
  it('summarises an archived scan in one row', () => {
    mockUseProjectArchives.mockReturnValue({ data: makeResponse([ARCHIVE]), isLoading: false })
    render(<ProjectArchives projectId="p1" />)

    const row = screen.getByRole('row', { name: /release\/2\.0/ })
    for (const text of ['release/2.0', 'abcdef1', '17', '2 C', '5 H', '321', '2', '2.0 KB']) {
      expect(within(row).getByText(text)).toBeInTheDocument()
    }
  })

  it('downloads the archive of the row', async () => {
    mockUseProjectArchives.mockReturnValue({ data: makeResponse([ARCHIVE]), isLoading: false })
    render(<ProjectArchives projectId="p1" />)

    fireEvent.click(screen.getByTitle('Download archive'))

    const [fetchFile] = vi.mocked(downloadServerFile).mock.calls[0]
    await fetchFile()
    expect(projectApi.downloadArchive).toHaveBeenCalledWith('p1', 's1')
  })

  it('restores the archive of the row after confirmation', () => {
    mockUseProjectArchives.mockReturnValue({ data: makeResponse([ARCHIVE]), isLoading: false })
    render(<ProjectArchives projectId="p1" />)

    fireEvent.click(screen.getByTitle('Restore to database (pinned)'))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Restore' }))

    expect(mockRestore).toHaveBeenCalledWith({ projectId: 'p1', scanId: 's1' }, expect.anything())
  })

  it('offers neither action without the archive permissions', () => {
    mockHasPermission.mockReturnValue(false)
    mockUseProjectArchives.mockReturnValue({ data: makeResponse([ARCHIVE]), isLoading: false })
    render(<ProjectArchives projectId="p1" />)

    expect(screen.queryByTitle('Download archive')).toBeNull()
    expect(screen.queryByTitle('Restore to database (pinned)')).toBeNull()
  })

  it('tells an unfiltered empty list apart from a filtered one', () => {
    render(<ProjectArchives projectId="p1" />)
    expect(screen.getByText('Scans will appear here when data retention archiving is enabled.')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-07-01' } })
    expect(screen.getByText('Try adjusting your filters.')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(screen.getByLabelText('From')).toHaveValue('')
  })
})

describe('ProjectArchives date filters', () => {
  it('starts the From day at local midnight, as the To day ends at local 23:59:59', () => {
    render(<ProjectArchives projectId="p1" />)

    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-07-01' } })
    fireEvent.change(screen.getByLabelText('To'), { target: { value: '2026-07-01' } })

    const calls = mockUseProjectArchives.mock.calls
    const filters = calls[calls.length - 1]?.[3] as ArchiveFilters | undefined
    expect(filters?.date_from).toBe(new Date('2026-07-01T00:00:00').toISOString())
    expect(filters?.date_to).toBe(new Date('2026-07-01T23:59:59').toISOString())
  })
})
