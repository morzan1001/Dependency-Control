import { describe, it, expect } from 'vitest'

import {
  getRiskColorClass,
  advisoryUrl,
  SEVERITY_CHART_COLORS,
  SEVERITY_ORDER,
  getSecretTreeStatusInfo,
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
