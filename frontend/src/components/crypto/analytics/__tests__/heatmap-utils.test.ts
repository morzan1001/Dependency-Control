import { describe, it, expect } from 'vitest'

import { heatmapCell, heatmapBgClass } from '../heatmap-utils'
import type { HotspotEntry } from '@/types/cryptoAnalytics'

function entry(over: Partial<HotspotEntry> = {}): HotspotEntry {
  return {
    key: 'RSA-2048',
    grouping_dimension: 'name',
    asset_count: 12,
    finding_count: 0,
    severity_mix: {},
    locations: ['a.py', 'b.py'],
    project_ids: [],
    first_seen: '',
    last_seen: '',
    ...over,
  }
}

// The API only returns a key's GLOBAL asset_count plus presence lists — there is
// no per-location count. The heatmap must therefore show PRESENCE per cell, not
// the global total fabricated into every cell (improvement audit #7).
describe('heatmapCell', () => {
  it('marks a present cell without fabricating a per-cell count', () => {
    const cell = heatmapCell(entry({ asset_count: 12 }), 'a.py', 'project', 20)
    expect(cell.present).toBe(true)
    // the cell label must NOT be the global asset_count
    expect(cell.label).not.toBe('12')
  })

  it('marks an absent cell empty', () => {
    const cell = heatmapCell(entry(), 'zzz.py', 'project', 20)
    expect(cell.present).toBe(false)
    expect(cell.label).toBe('')
  })

  it('uses the same row-level intensity for every present cell (key prevalence)', () => {
    const e = entry({ asset_count: 10, locations: ['a.py', 'b.py'] })
    const a = heatmapCell(e, 'a.py', 'project', 20)
    const b = heatmapCell(e, 'b.py', 'project', 20)
    expect(a.intensityRatio).toBe(b.intensityRatio)
    expect(a.intensityRatio).toBeCloseTo(0.5) // 10 / max(20)
  })

  it('groups by project_ids when scope is not project', () => {
    const e = entry({ locations: [], project_ids: ['p1'] })
    expect(heatmapCell(e, 'p1', 'organization', 5).present).toBe(true)
    expect(heatmapCell(e, 'p2', 'organization', 5).present).toBe(false)
  })
})

describe('heatmapBgClass', () => {
  it('is muted when absent regardless of ratio', () => {
    expect(heatmapBgClass(false, 1)).toContain('muted')
  })

  it('scales intensity for present cells', () => {
    expect(heatmapBgClass(true, 0.9)).toContain('red')
    expect(heatmapBgClass(true, 0.1)).toContain('yellow')
  })
})
