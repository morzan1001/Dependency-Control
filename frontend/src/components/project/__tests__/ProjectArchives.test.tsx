// Force a non-UTC timezone so date parsing is exercised in local time.
process.env.TZ = 'America/New_York'

import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ProjectArchives } from '../ProjectArchives'
import type { ArchiveFilters, ArchiveListItem, ArchiveListResponse } from '@/types/archive'

const mockUseProjectArchives = vi.fn()

vi.mock('@/hooks/queries/use-projects', () => ({
  useProjectArchives: (...args: unknown[]) => mockUseProjectArchives(...args),
  useArchiveBranches: () => ({ data: ['main'] }),
  useRestoreArchive: () => ({ mutate: vi.fn(), isPending: false }),
}))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ hasPermission: () => true }) }))

function makeResponse(items: ArchiveListItem[]): ArchiveListResponse {
  return { items, total: items.length, page: 1, size: 20, pages: 1 }
}

beforeEach(() => {
  mockUseProjectArchives.mockReset()
  mockUseProjectArchives.mockReturnValue({ data: makeResponse([]), isLoading: false })
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
