import { isScanUsable } from '@/lib/scan-status'
import type { EnhancedStats, Scan } from '@/types/scan'

export interface ResolvedRun {
  scanId: string
  stats: EnhancedStats
  status: string
  date: string
}

// latest_run appears when a rescan is queued and keeps partial stats on failure, so every field comes off one side.
export function resolveRun(scan: Scan): ResolvedRun {
  const run = scan.latest_run
  if (run?.stats && isScanUsable(run.status)) {
    return {
      scanId: run.scan_id,
      stats: run.stats,
      status: run.status,
      date: run.completed_at || run.created_at || scan.created_at,
    }
  }
  return {
    scanId: scan.id,
    stats: scan.stats || {},
    status: scan.status,
    date: scan.completed_at || scan.created_at,
  }
}
