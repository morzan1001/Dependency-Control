import { describe, it, expect } from 'vitest'

import { highestRiskBranch, initialBranchSelection, outranksBranchTip } from '@/lib/branches'
import type { BranchInfo } from '@/types/project'
import type { Scan } from '@/types/scan'

function branch(name: string, overrides: Partial<BranchInfo> = {}): BranchInfo {
  return { name, is_active: true, last_scan_at: '2026-08-14T00:00:00Z', is_default: false, ...overrides }
}

function scan(name: string, stats: Record<string, number>): Scan {
  return { id: `scan-${name}`, branch: name, status: 'completed', created_at: '2026-08-14T00:00:00Z', stats } as unknown as Scan
}

describe('initialBranchSelection', () => {
  it('selects only the default branch, never every active branch', () => {
    const branches = [branch('main', { is_default: true }), branch('feature-a'), branch('feature-b')]
    expect(initialBranchSelection(branches)).toEqual(['main'])
  })

  it('ignores a default flag on a deleted branch', () => {
    const branches = [branch('main', { is_default: true, is_active: false }), branch('feature-a')]
    expect(initialBranchSelection(branches)).toEqual([])
  })
})

describe('highestRiskBranch', () => {
  it('picks the worst branch instead of blending several', () => {
    const scans = {
      main: scan('main', { risk_score: 12, critical: 1, high: 4 }),
      release: scan('release', { risk_score: 40, critical: 3, high: 9 }),
      feature: scan('feature', { risk_score: 12, critical: 2, high: 1 }),
    }
    expect(highestRiskBranch(scans)).toBe('release')
  })

  it('breaks risk-score ties on critical then high, then alphabetically', () => {
    const scans = {
      zeta: scan('zeta', { risk_score: 5, critical: 1, high: 1 }),
      alpha: scan('alpha', { risk_score: 5, critical: 1, high: 1 }),
    }
    expect(highestRiskBranch(scans)).toBe('alpha')
  })

  it('returns null without scans', () => {
    expect(highestRiskBranch({})).toBeNull()
  })
})

const TIP_BUILT_AT = '2026-08-10T00:00:00Z'
const RESCAN_RAN_AT = '2026-08-20T00:00:00Z'
const OLDER_BUILD_AT = '2026-08-01T00:00:00Z'

function build(id: string, created_at: string, is_rescan = false): Scan {
  return { id, branch: 'main', status: 'completed', created_at, is_rescan, stats: {} } as unknown as Scan
}

describe('outranksBranchTip', () => {
  it('keeps the branch tip when a rescan of an older commit ran since', () => {
    const tip = build('tip', TIP_BUILT_AT)
    expect(outranksBranchTip(build('rescan', RESCAN_RAN_AT, true), tip)).toBe(false)
  })

  it('lets a real build displace a rescan that ran later', () => {
    const rescan = build('rescan', RESCAN_RAN_AT, true)
    expect(outranksBranchTip(build('tip', TIP_BUILT_AT), rescan)).toBe(true)
  })

  it('ranks two real builds by build time', () => {
    const older = build('older', OLDER_BUILD_AT)
    expect(outranksBranchTip(build('tip', TIP_BUILT_AT), older)).toBe(true)
    expect(outranksBranchTip(older, build('tip', TIP_BUILT_AT))).toBe(false)
  })

  it('takes a rescan when the branch holds nothing else', () => {
    expect(outranksBranchTip(build('rescan', RESCAN_RAN_AT, true), undefined)).toBe(true)
  })
})
