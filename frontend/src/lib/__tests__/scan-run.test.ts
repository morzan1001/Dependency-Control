import { describe, expect, it } from 'vitest'

import { resolveRun } from '@/lib/scan-run'
import type { Scan } from '@/types/scan'

const SCAN_ID = 'scan-1'
const RESCAN_ID = 'scan-1-rescan'
const CREATED_AT = '2026-08-01T00:00:00Z'
const COMPLETED_AT = '2026-08-01T01:00:00Z'
const RESCAN_COMPLETED_AT = '2026-08-20T00:00:00Z'
const COMPLETED = 'completed'
const PENDING = 'pending'
const OWN_CRITICAL = 7
const RESCANNED_CRITICAL = 2

// Annotated, not inferred: an inferred fixture drops a field from the type silently.
function makeScan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: SCAN_ID,
    project_id: 'p1',
    branch: 'main',
    status: COMPLETED,
    created_at: CREATED_AT,
    completed_at: COMPLETED_AT,
    stats: { critical: OWN_CRITICAL },
    ...overrides,
  }
}

describe('resolveRun', () => {
  it('reads a finished rescan, since that is what the scan now reports', () => {
    const scan = makeScan({
      latest_run: {
        scan_id: RESCAN_ID,
        status: COMPLETED,
        stats: { critical: RESCANNED_CRITICAL },
        completed_at: RESCAN_COMPLETED_AT,
      },
    })

    expect(resolveRun(scan)).toEqual({
      scanId: RESCAN_ID,
      stats: { critical: RESCANNED_CRITICAL },
      status: COMPLETED,
      date: RESCAN_COMPLETED_AT,
    })
  })

  it('keeps the numbers the scan itself reports while its rescan is only queued', () => {
    const scan = makeScan({ latest_run: { scan_id: RESCAN_ID, status: PENDING, created_at: RESCAN_COMPLETED_AT } })

    expect(resolveRun(scan)).toEqual({
      scanId: SCAN_ID,
      stats: { critical: OWN_CRITICAL },
      status: COMPLETED,
      date: COMPLETED_AT,
    })
  })

  it('keeps the numbers the scan itself reports when a finished rescan reports none', () => {
    const scan = makeScan({ latest_run: { scan_id: RESCAN_ID, status: COMPLETED, stats: null } })

    expect(resolveRun(scan).stats).toEqual({ critical: OWN_CRITICAL })
    expect(resolveRun(scan).scanId).toBe(SCAN_ID)
  })

  it('falls back to an empty stat set rather than inventing zeroes', () => {
    expect(resolveRun(makeScan({ stats: null })).stats).toEqual({})
  })
})
