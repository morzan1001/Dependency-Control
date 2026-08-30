import { describe, it, expect } from 'vitest'

import {
  getRiskColorClass,
  advisoryUrl,
  SEVERITY_CHART_COLORS,
  SEVERITY_ORDER,
  getSecretTreeStatusInfo,
  isSecretDeprioritized,
  getSecretRemediationHint,
  getReachabilityDisplay,
} from '../finding-utils'

// Color bands are on the backend's 0-100 combined-risk scale, not the 0-10 CVSS scale.
describe('getRiskColorClass (0-100 scale)', () => {
  it('paints a high 0-100 score critical', () => {
    expect(getRiskColorClass(85)).toBe('text-severity-critical')
    expect(getRiskColorClass(70)).toBe('text-severity-critical')
  })

  it('paints a mid-high score high', () => {
    expect(getRiskColorClass(50)).toBe('text-severity-high')
    expect(getRiskColorClass(40)).toBe('text-severity-high')
  })

  it('paints a mid score medium', () => {
    expect(getRiskColorClass(30)).toBe('text-severity-medium')
    expect(getRiskColorClass(20)).toBe('text-severity-medium')
  })

  it('paints a genuinely low score muted (not critical)', () => {
    expect(getRiskColorClass(12)).toBe('text-muted-foreground')
    expect(getRiskColorClass(0)).toBe('text-muted-foreground')
  })
})

describe('advisoryUrl', () => {
  it('maps a CVE id to its NVD detail page', () => {
    expect(advisoryUrl('CVE-2021-44228')).toBe(
      'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
    )
  })

  it('maps a GHSA id to its GitHub advisory page', () => {
    expect(advisoryUrl('GHSA-jfh8-c2jp-5v3q')).toBe(
      'https://github.com/advisories/GHSA-jfh8-c2jp-5v3q'
    )
  })

  it('returns null for identifiers with no well-known advisory page', () => {
    expect(advisoryUrl('log4shell')).toBeNull()
    expect(advisoryUrl('')).toBeNull()
  })
})

describe('severity chart tokens', () => {
  it('exposes a hex colour for every severity, most-severe first', () => {
    expect(SEVERITY_ORDER).toEqual([
      'CRITICAL',
      'HIGH',
      'MEDIUM',
      'LOW',
      'NEGLIGIBLE',
      'INFO',
      'UNKNOWN',
    ])
    for (const severity of SEVERITY_ORDER) {
      expect(SEVERITY_CHART_COLORS[severity]).toMatch(/^#[0-9a-f]{6}$/)
    }
  })

  it('keeps critical/high/medium/low aligned with the tailwind severity palette', () => {
    expect(SEVERITY_CHART_COLORS.CRITICAL).toBe('#dc2626')
    expect(SEVERITY_CHART_COLORS.HIGH).toBe('#f97316')
    expect(SEVERITY_CHART_COLORS.MEDIUM).toBe('#eab308')
    expect(SEVERITY_CHART_COLORS.LOW).toBe('#3b82f6')
  })
})

describe('getSecretTreeStatusInfo', () => {
  it('labels a file still in the current tree', () => {
    const info = getSecretTreeStatusInfo(true)
    expect(info?.label).toBe('In current code')
    expect(info?.className).toContain('text-success')
  })

  it('labels a file only in history as historical', () => {
    const info = getSecretTreeStatusInfo(false)
    expect(info?.label).toBe('Only in history')
    expect(info?.className).toContain('text-severity-medium')
  })

  it('returns null when tree status is unknown', () => {
    expect(getSecretTreeStatusInfo(null)).toBeNull()
    expect(getSecretTreeStatusInfo(undefined)).toBeNull()
  })
})

describe('isSecretDeprioritized', () => {
  const secret = (in_current_tree: boolean | null | undefined, verified?: boolean) => ({
    type: 'secret',
    details: { in_current_tree, verified },
  })

  it('is true for an unverified secret gone from the current tree', () => {
    expect(isSecretDeprioritized(secret(false, false))).toBe(true)
    expect(isSecretDeprioritized(secret(false, undefined))).toBe(true)
  })

  it('is false for a verified secret even when gone from the tree (live leak)', () => {
    expect(isSecretDeprioritized(secret(false, true))).toBe(false)
  })

  it('is false for a secret still in the current tree', () => {
    expect(isSecretDeprioritized(secret(true, false))).toBe(false)
  })

  it('is false when tree status is unknown', () => {
    expect(isSecretDeprioritized(secret(null))).toBe(false)
    expect(isSecretDeprioritized(secret(undefined))).toBe(false)
  })

  it('is false for non-secret findings regardless of tree state', () => {
    expect(isSecretDeprioritized({ type: 'vulnerability', details: { in_current_tree: false } })).toBe(false)
  })
})

describe('getSecretRemediationHint', () => {
  it('flags a verified history-only secret as a live credential to rotate now', () => {
    const hint = getSecretRemediationHint(true, false)
    expect(hint?.tone).toBe('danger')
    expect(hint?.text).toMatch(/rotate/i)
    expect(hint?.text).toMatch(/history/i)
  })

  it('tells the user an unverified history-only secret cannot be deleted away', () => {
    const hint = getSecretRemediationHint(false, false)
    expect(hint?.tone).toBe('muted')
    expect(hint?.text).toMatch(/history/i)
    expect(hint?.text).toMatch(/rotate|waive/i)
  })

  it('tells the user to remove an in-tree secret from the code and rotate', () => {
    const hint = getSecretRemediationHint(false, true)
    expect(hint?.tone).toBe('muted')
    expect(hint?.text).toMatch(/rotate/i)
  })

  it('returns null when tree status is unknown', () => {
    expect(getSecretRemediationHint(false, null)).toBeNull()
    expect(getSecretRemediationHint(true, undefined)).toBeNull()
  })
})

describe('getReachabilityDisplay', () => {
  it('treats a missing verdict as unknown, never as unreachable', () => {
    expect(getReachabilityDisplay({})).toEqual({ verdict: 'unknown', label: 'Reachability unknown' })
    expect(getReachabilityDisplay({ is_reachable: null })).toEqual({
      verdict: 'unknown',
      label: 'Reachability unknown',
    })
  })

  it('reports only an explicit false as not reachable', () => {
    expect(getReachabilityDisplay({ is_reachable: false })).toEqual({
      verdict: 'unreachable',
      label: 'Not Reachable',
    })
  })

  it('labels a symbol-level match as confirmed and anything else as imported', () => {
    expect(getReachabilityDisplay({ is_reachable: true, analysis_level: 'symbol' })).toEqual({
      verdict: 'reachable',
      label: 'Reachable (confirmed)',
    })
    expect(getReachabilityDisplay({ is_reachable: true, analysis_level: 'import' })).toEqual({
      verdict: 'reachable',
      label: 'Reachable (imported)',
    })
    expect(getReachabilityDisplay({ is_reachable: true })).toEqual({
      verdict: 'reachable',
      label: 'Reachable (imported)',
    })
  })
})
