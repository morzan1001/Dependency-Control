import { describe, it, expect } from 'vitest'

import { heatmapCell, heatmapBgClass } from '../heatmap-utils'
import type { HotspotEntry } from '@/types/cryptoAnalytics'

const MAX_ASSET_COUNT = 20

function entry(over: Partial<HotspotEntry> = {}): HotspotEntry {
  return {
    key: 'RSA-2048',
    grouping_dimension: 'name',
    asset_count: 12,
    finding_count: 0,
    severity_mix: {},
    locations: ['a.py', 'b.py'],
    locations_complete: true,
    project_ids: [],
    first_seen: '',
    last_seen: '',
    ...over,
  }
}

// API returns only a global asset_count plus presence lists, so cells show presence, not a per-cell count.
describe('heatmapCell', () => {
  it('marks a present cell without fabricating a per-cell count', () => {
    const cell = heatmapCell(entry({ asset_count: 12 }), 'a.py', 'project', MAX_ASSET_COUNT)
    expect(cell.state).toBe('present')
    expect(cell.label).not.toBe('12')
  })

  it('marks an absent cell empty when the row lists every location it has', () => {
    const cell = heatmapCell(entry(), 'zzz.py', 'project', MAX_ASSET_COUNT)
    expect(cell.state).toBe('absent')
    expect(cell.label).toBe('')
  })

  it('marks an unlisted cell unknown when the row lists only a sample', () => {
    const cell = heatmapCell(entry({ locations_complete: false }), 'zzz.py', 'project', MAX_ASSET_COUNT)
    expect(cell.state).toBe('unknown')
    expect(cell.title).toContain('unknown')
  })

  it('uses the same row-level intensity for every present cell (key prevalence)', () => {
    const e = entry({ asset_count: 10, locations: ['a.py', 'b.py'] })
    const a = heatmapCell(e, 'a.py', 'project', MAX_ASSET_COUNT)
    const b = heatmapCell(e, 'b.py', 'project', MAX_ASSET_COUNT)
    expect(a.intensityRatio).toBe(b.intensityRatio)
    expect(a.intensityRatio).toBeCloseTo(0.5) // 10 / max(20)
  })

  it('groups by project_ids when scope is not project', () => {
    const e = entry({ locations: [], locations_complete: false, project_ids: ['p1'] })
    expect(heatmapCell(e, 'p1', 'global', 5).state).toBe('present')
    // project_ids is the whole set, so a sampled location list cannot make a project cell unknown.
    expect(heatmapCell(e, 'p2', 'global', 5).state).toBe('absent')
  })
})

describe('heatmapBgClass', () => {
  it('is muted when absent regardless of ratio', () => {
    expect(heatmapBgClass('absent', 1)).toContain('muted')
  })

  it('scales intensity for present cells', () => {
    expect(heatmapBgClass('present', 0.9)).toContain('red')
    expect(heatmapBgClass('present', 0.1)).toContain('yellow')
  })

  it('does not colour an unknown cell as a reading', () => {
    expect(heatmapBgClass('unknown', 0.9)).not.toContain('red')
  })
})
