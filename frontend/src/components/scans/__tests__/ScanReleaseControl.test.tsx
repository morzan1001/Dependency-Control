import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ScanReleaseControl } from '../ScanReleaseControl'
import { formatDateTime } from '@/lib/utils'
import type { ReleaseItem, ReleaseListResponse } from '@/types/release'
import type { Scan } from '@/types/scan'

const PROJECT_ID = 'p1'
const SCAN_ID = 'scan-1'
const OTHER_SCAN_ID = 'scan-2'
const COMMIT_HASH = 'a'.repeat(40)
const PRODUCTION = 'production'
const STAGING = 'staging'
const PRODUCTION_VERSION = 'v1.2.3'
const STAGING_VERSION = 'v1.3.0-rc1'
const PRODUCTION_RELEASED_AT = '2026-09-01T10:00:00Z'
const STAGING_RELEASED_AT = '2026-09-02T11:00:00Z'
const MARK_BUTTON = 'Mark as release'
const GENERIC_RELEASE_LABEL = 'Release'
const FIRST_PAGE = 1
const SINGLE_WITHDRAW_BUTTON = 1

const mockMark = vi.fn()
const mockUnmark = vi.fn()
const mockUseProjectReleases = vi.fn()

vi.mock('@/hooks/queries/use-releases', () => ({
  useProjectReleases: (...args: unknown[]) => mockUseProjectReleases(...args),
  useMarkRelease: () => ({ mutate: mockMark, isPending: false }),
  useUnmarkRelease: () => ({ mutate: mockUnmark, isPending: false }),
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

function makeScan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: SCAN_ID,
    project_id: PROJECT_ID,
    branch: 'main',
    commit_hash: COMMIT_HASH,
    status: 'completed',
    created_at: '2026-09-01T00:00:00Z',
    is_release: false,
    ...overrides,
  }
}

function makeRelease(overrides: Partial<ReleaseItem> = {}): ReleaseItem {
  return {
    scan_id: SCAN_ID,
    project_id: PROJECT_ID,
    environment: PRODUCTION,
    version: PRODUCTION_VERSION,
    released_at: PRODUCTION_RELEASED_AT,
    commit_hash: COMMIT_HASH,
    branch: 'main',
    scan_status: 'completed',
    analysis_scan_id: SCAN_ID,
    ...overrides,
  }
}

function renderControl(scan: Scan, items: ReleaseItem[] = []) {
  const releases: ReleaseListResponse = {
    items,
    total: items.length,
    page: FIRST_PAGE,
    size: items.length,
  }
  mockUseProjectReleases.mockReturnValue({ data: releases })
  return render(<ScanReleaseControl projectId={PROJECT_ID} scan={scan} />)
}

beforeEach(() => vi.clearAllMocks())

describe('ScanReleaseControl', () => {
  it('offers to mark a plain scan', () => {
    renderControl(makeScan())

    fireEvent.click(screen.getByRole('button', { name: MARK_BUTTON }))

    expect(mockMark).toHaveBeenCalledWith(
      { projectId: PROJECT_ID, payload: { commit_hash: COMMIT_HASH } },
      expect.anything(),
    )
  })

  it('cannot mark a scan that has no commit', () => {
    renderControl(makeScan({ commit_hash: undefined }))

    expect(screen.getByRole('button', { name: MARK_BUTTON })).toBeDisabled()
  })

  it('withdraws the environment whose button was pressed', () => {
    renderControl(makeScan({ is_release: true }), [
      makeRelease({ environment: STAGING, version: STAGING_VERSION, released_at: STAGING_RELEASED_AT }),
      makeRelease(),
    ])

    expect(screen.getByLabelText(`Release ${STAGING_VERSION} in ${STAGING}`)).toBeInTheDocument()
    expect(screen.getByLabelText(`Release ${PRODUCTION_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: MARK_BUTTON })).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: `Withdraw from ${STAGING}` }))

    expect(mockUnmark).toHaveBeenCalledWith(
      { projectId: PROJECT_ID, scanId: SCAN_ID, environment: STAGING },
      expect.anything(),
    )
  })

  it('names when each environment took the release', () => {
    renderControl(makeScan({ is_release: true }), [
      makeRelease({ environment: STAGING, released_at: STAGING_RELEASED_AT }),
      makeRelease(),
    ])

    expect(screen.getByText(`Released ${formatDateTime(STAGING_RELEASED_AT)}`)).toBeInTheDocument()
    expect(screen.getByText(`Released ${formatDateTime(PRODUCTION_RELEASED_AT)}`)).toBeInTheDocument()
  })

  it('leaves another scan of the project alone', () => {
    renderControl(makeScan({ is_release: true }), [
      makeRelease({ scan_id: OTHER_SCAN_ID, environment: STAGING, version: STAGING_VERSION }),
      makeRelease(),
    ])

    expect(screen.queryByLabelText(`Release ${STAGING_VERSION} in ${STAGING}`)).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /^Withdraw from/ })).toHaveLength(SINGLE_WITHDRAW_BUTTON)
  })

  it('keeps the badge for a release whose record it cannot see', () => {
    renderControl(makeScan({ is_release: true }))

    expect(screen.getByLabelText(GENERIC_RELEASE_LABEL)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Withdraw from/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: MARK_BUTTON })).not.toBeInTheDocument()
  })
})
