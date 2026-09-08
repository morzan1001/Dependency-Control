import type { AnalyticsScope, HotspotEntry } from '@/types/cryptoAnalytics'

/** A blank cell on a row whose location list is a sample means "not known", not "not there". */
export type CellState = 'present' | 'absent' | 'unknown'

export interface HeatmapCell {
  state: CellState
  /** Row-level intensity (0..1); the API exposes no per-location count. */
  intensityRatio: number
  label: string
  title: string
}

function cellState(entry: HotspotEntry, column: string, scope: AnalyticsScope): CellState {
  if (scope !== 'project') {
    return entry.project_ids.includes(column) ? 'present' : 'absent'
  }
  if (entry.locations.includes(column)) return 'present'
  return entry.locations_complete ? 'absent' : 'unknown'
}

const CELL_LABEL: Record<CellState, string> = { present: '•', unknown: '?', absent: '' }

function cellTitle(entry: HotspotEntry, column: string, state: CellState): string {
  if (state === 'present') {
    return `${entry.key} present in ${column} (key total across scope: ${entry.asset_count})`
  }
  if (state === 'unknown') {
    return `${entry.key}: unknown for ${column} — only some of this key's locations are listed`
  }
  return `${entry.key}: not present in ${column}`
}

export function heatmapCell(
  entry: HotspotEntry,
  column: string,
  scope: AnalyticsScope,
  max: number,
): HeatmapCell {
  const state = cellState(entry, column, scope)
  return {
    state,
    intensityRatio: state === 'present' ? entry.asset_count / Math.max(max, 1) : 0,
    label: CELL_LABEL[state],
    title: cellTitle(entry, column, state),
  }
}

export function heatmapBgClass(state: CellState, ratio: number): string {
  if (state === 'unknown') return 'bg-muted/60 text-muted-foreground'
  if (state === 'absent') return 'bg-muted/30'
  if (ratio >= 0.8) return 'bg-red-500/80 text-white'
  if (ratio >= 0.5) return 'bg-orange-500/70'
  if (ratio >= 0.25) return 'bg-yellow-500/50'
  return 'bg-yellow-500/20'
}
