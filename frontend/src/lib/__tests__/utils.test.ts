import { describe, it, expect } from 'vitest'

import { formatUpdatesPerMonth } from '../utils'

describe('formatUpdatesPerMonth', () => {
  it('reports N/A when no calendar window was requested', () => {
    expect(formatUpdatesPerMonth(null)).toBe('N/A')
    expect(formatUpdatesPerMonth(undefined)).toBe('N/A')
  })

  it('keeps a measured rate of zero distinct from N/A', () => {
    expect(formatUpdatesPerMonth(0)).toBe('0')
  })

  it('renders a rate as given', () => {
    expect(formatUpdatesPerMonth(3.72)).toBe('3.72')
  })
})
