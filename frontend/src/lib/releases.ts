import type { ScanWithReleases } from '@/types/scan'

// Scan.is_release is denormalised from the release rows, so a scan can hold the flag with no row:
// a mark whose row write failed, or a flag set by hand. It is still a release, just an unnamed one.
export const hasUnrecordedRelease = (scan: ScanWithReleases): boolean =>
  scan.is_release === true && scan.releases.length === 0
