import { isScanUsable } from '@/lib/scan-status'
import type { EnhancedStats, Scan } from '@/types/scan'

export interface ResolvedRun {
  scanId: string
  stats: EnhancedStats
  status: string
  date: string
}

// A rescan announces itself on latest_run the moment it is queued, and a failed one still summarises
// whatever it managed to persist. Identity, numbers, status and date come off one side together, so
// nothing can attribute a run's stats to another scan or let a partial count replace a complete one.
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
