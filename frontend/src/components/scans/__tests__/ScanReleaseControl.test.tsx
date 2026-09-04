import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ScanReleaseControl } from '../ScanReleaseControl'
import { formatDateTime } from '@/lib/utils'
import type { ScanReleaseRef, ScanWithReleases } from '@/types/scan'

const PROJECT_ID = 'p1'
const SCAN_ID = 'scan-1'
const COMMIT_HASH = 'a'.repeat(40)
const PRODUCTION = 'production'
const STAGING = 'staging'
const PRODUCTION_VERSION = 'v1.2.3'
const STAGING_VERSION = 'v1.3.0-rc1'
const PRODUCTION_RELEASED_AT = '2026-09-01T10:00:00Z'
const STAGING_RELEASED_AT = '2026-09-02T11:00:00Z'
const MARK_BUTTON = 'Mark as release'
const GENERIC_RELEASE_LABEL = 'Release'
const ENVIRONMENT_FIELD = 'Environment to release to'
const OFF_PATTERN_ENVIRONMENT = 'Pre-Prod!'
const OFF_PATTERN_HINT = /lowercase letters/i

const mockMark = vi.fn()
const mockUnmark = vi.fn()

vi.mock('@/hooks/queries/use-releases', () => ({
  useMarkRelease: () => ({ mutate: mockMark, isPending: false }),
  useUnmarkRelease: () => ({ mutate: mockUnmark, isPending: false }),
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

function makeScan(overrides: Partial<ScanWithReleases> = {}): ScanWithReleases {
  return {
    id: SCAN_ID,
    project_id: PROJECT_ID,
    branch: 'main',
    commit_hash: COMMIT_HASH,
    status: 'completed',
    created_at: '2026-09-01T00:00:00Z',
    is_release: false,
    releases: [],
    ...overrides,
  }
}

function makeRelease(overrides: Partial<ScanReleaseRef> = {}): ScanReleaseRef {
  return {
    environment: PRODUCTION,
    version: PRODUCTION_VERSION,
    released_at: PRODUCTION_RELEASED_AT,
    ...overrides,
  }
}

function releasedScan(releases: ScanReleaseRef[]): ScanWithReleases {
  return makeScan({ is_release: true, releases })
}

beforeEach(() => vi.clearAllMocks())

describe('ScanReleaseControl', () => {
  it('marks a plain scan into the default environment, leaving the version to the backend', () => {
    render(<ScanReleaseControl projectId={PROJECT_ID} scan={makeScan()} />)

    fireEvent.click(screen.getByRole('button', { name: MARK_BUTTON }))

    expect(mockMark).toHaveBeenCalledWith(
      { projectId: PROJECT_ID, payload: { commit_hash: COMMIT_HASH, environment: PRODUCTION } },
      expect.anything(),
    )
  })

  it('promotes a staging release to the environment that was typed', () => {
    const scan = releasedScan([makeRelease({ environment: STAGING, version: STAGING_VERSION })])
    render(<ScanReleaseControl projectId={PROJECT_ID} scan={scan} />)

    fireEvent.change(screen.getByLabelText(ENVIRONMENT_FIELD), { target: { value: PRODUCTION } })
    fireEvent.click(screen.getByRole('button', { name: MARK_BUTTON }))

    expect(mockMark).toHaveBeenCalledWith(
      { projectId: PROJECT_ID, payload: { commit_hash: COMMIT_HASH, environment: PRODUCTION } },
      expect.anything(),
    )
  })

  it('does not offer to re-mark an environment the scan already holds', () => {
    render(<ScanReleaseControl projectId={PROJECT_ID} scan={releasedScan([makeRelease()])} />)

    expect(screen.getByRole('button', { name: MARK_BUTTON })).toBeDisabled()
    expect(screen.getByText(`Already released to ${PRODUCTION}.`)).toBeInTheDocument()
  })

  it('rejects an environment the backend would refuse instead of requesting it', () => {
    render(<ScanReleaseControl projectId={PROJECT_ID} scan={makeScan()} />)

    fireEvent.change(screen.getByLabelText(ENVIRONMENT_FIELD), { target: { value: OFF_PATTERN_ENVIRONMENT } })
    fireEvent.click(screen.getByRole('button', { name: MARK_BUTTON }))

    expect(screen.getByRole('button', { name: MARK_BUTTON })).toBeDisabled()
    expect(screen.getByText(OFF_PATTERN_HINT)).toBeInTheDocument()
    expect(mockMark).not.toHaveBeenCalled()
  })

  it('cannot mark a scan that has no commit', () => {
    render(<ScanReleaseControl projectId={PROJECT_ID} scan={makeScan({ commit_hash: undefined })} />)

    expect(screen.getByRole('button', { name: MARK_BUTTON })).toBeDisabled()
  })

  it('withdraws the environment whose button was pressed', () => {
    const scan = releasedScan([
      makeRelease({ environment: STAGING, version: STAGING_VERSION, released_at: STAGING_RELEASED_AT }),
      makeRelease(),
    ])
    render(<ScanReleaseControl projectId={PROJECT_ID} scan={scan} />)

    expect(screen.getByLabelText(`Release ${STAGING_VERSION} in ${STAGING}`)).toBeInTheDocument()
    expect(screen.getByLabelText(`Release ${PRODUCTION_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: `Withdraw from ${STAGING}` }))

    expect(mockUnmark).toHaveBeenCalledWith(
      { projectId: PROJECT_ID, scanId: SCAN_ID, environment: STAGING },
      expect.anything(),
    )
  })

  it('names when each environment took the release', () => {
    const scan = releasedScan([
      makeRelease({ environment: STAGING, released_at: STAGING_RELEASED_AT }),
      makeRelease(),
    ])
    render(<ScanReleaseControl projectId={PROJECT_ID} scan={scan} />)

    expect(screen.getByText(`Released ${formatDateTime(STAGING_RELEASED_AT)}`)).toBeInTheDocument()
    expect(screen.getByText(`Released ${formatDateTime(PRODUCTION_RELEASED_AT)}`)).toBeInTheDocument()
  })

  it('keeps the badge for a release whose record it cannot see', () => {
    render(<ScanReleaseControl projectId={PROJECT_ID} scan={releasedScan([])} />)

    expect(screen.getByLabelText(GENERIC_RELEASE_LABEL)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Withdraw from/ })).not.toBeInTheDocument()
    // Nothing names the environments it holds, so every one of them stays markable.
    expect(screen.getByRole('button', { name: MARK_BUTTON })).toBeEnabled()
  })
})
