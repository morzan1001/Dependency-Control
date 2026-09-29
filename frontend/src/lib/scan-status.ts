export const SCAN_STATUS_COMPLETED = 'completed'
export const SCAN_STATUS_COMPLETED_WITH_ERRORS = 'completed_with_errors'
export const SCAN_STATUS_FAILED = 'failed'

/** Scans whose results are usable for stats, deltas and rollups. */
export const isScanUsable = (status?: string): boolean =>
  status === SCAN_STATUS_COMPLETED || status === SCAN_STATUS_COMPLETED_WITH_ERRORS

/** Scans the backend is still analysing: nothing to rescan or read yet. */
export const isScanInProgress = (status?: string): boolean => status === 'pending' || status === 'processing'
