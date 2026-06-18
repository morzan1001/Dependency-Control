import type { AnalyticsScope, HotspotEntry } from '@/types/cryptoAnalytics'

export interface HeatmapCell {
  /** Whether the key occurs in this column (location or project). */
  present: boolean
  /**
   * Row-level intensity (0..1) = the key's global asset_count / max across keys.
   * It reflects how prevalent the KEY is overall — a row property, identical for
   * every present cell in the row — NOT a per-cell density. The API exposes no
   * per-location count, so a per-cell number would be fabricated.
   */
  intensityRatio: number
  /** Cell content: a presence marker, never a fabricated per-cell count. */
  label: string
  /** Tooltip text. */
  title: string
}

/**
 * Decide how to render one (key, column) heatmap cell.
 *
 * Previously every present cell was painted with the key's GLOBAL asset_count,
 * so a key present in N locations showed the same total in all N cells and read
 * as "N assets in this location" — false. We show presence instead, with the
 * key's overall prevalence as the (row-level) color intensity (audit #7).
 */
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
