import { describe, it, expect } from 'vitest'

import { formatUpdatesPerMonth, toggle } from '../utils'

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

describe('toggle', () => {
  it('adds a value the list lacks and removes one it holds, leaving the list itself alone', () => {
    const list = ['a', 'b']

    expect(toggle(list, 'c')).toEqual(['a', 'b', 'c'])
    expect(toggle(list, 'a')).toEqual(['b'])
    expect(list).toEqual(['a', 'b'])
  })
})
