import type { AnalyticsScope, HotspotEntry } from '@/types/cryptoAnalytics'

export interface HeatmapCell {
  present: boolean
  /** Row-level intensity (0..1); the API exposes no per-location count. */
  intensityRatio: number
  label: string
  title: string
}

export function heatmapCell(
  entry: HotspotEntry,
  column: string,
  scope: AnalyticsScope,
  max: number,
): HeatmapCell {
  const present = scope === 'project' ? entry.locations.includes(column) : entry.project_ids.includes(column)
  return {
    present,
    intensityRatio: present ? entry.asset_count / Math.max(max, 1) : 0,
    label: present ? '•' : '',
    title: present
      ? `${entry.key} present in ${column} (key total across scope: ${entry.asset_count})`
      : `${entry.key}: not present in ${column}`,
  }
}

export function heatmapBgClass(present: boolean, ratio: number): string {
  if (!present) return 'bg-muted/30'
  if (ratio >= 0.8) return 'bg-red-500/80 text-white'
  if (ratio >= 0.5) return 'bg-orange-500/70'
  if (ratio >= 0.25) return 'bg-yellow-500/50'
  return 'bg-yellow-500/20'
}
