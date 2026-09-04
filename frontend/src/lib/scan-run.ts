import type { EnhancedStats, Scan } from '@/types/scan'

export interface ResolvedRun {
  scanId: string
  stats: EnhancedStats
  status: string
  date: string
}

// A rescan announces itself on latest_run the moment it is queued, with nothing analysed. Identity,
// numbers, status and date come off one side together, so nothing can attribute a run's stats to
// another scan or read a queued rescan's empty summary as a clean result.
export function resolveRun(scan: Scan): ResolvedRun {
  const run = scan.latest_run
  if (run?.stats) {
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
