import { describe, it, expect } from 'vitest'

import { getRiskColorClass } from '../finding-utils'

// The backend combined risk score is on a 0-100 scale, so the color bands must
// be too. The previous 0-10 (CVSS) thresholds painted almost every row
// critical-red and made a genuinely low score look the most severe
// (improvement audit #5).
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
