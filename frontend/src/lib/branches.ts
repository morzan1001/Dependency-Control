import { BranchInfo } from '@/types/project'
import { Scan } from '@/types/scan'

/**
 * Exactly one branch, resolved by the backend. Selecting every active branch instead
 * sums the same finding once per branch, inflating every headline counter.
 */
export function initialBranchSelection(branches: BranchInfo[]): string[] {
  const preferred = branches.find(b => b.is_default && b.is_active)
  return preferred ? [preferred.name] : []
}

function severityRank(scan: Scan): number[] {
  return [scan.stats?.risk_score ?? 0, scan.stats?.critical ?? 0, scan.stats?.high ?? 0]
}

function isHigher(candidate: number[], current: number[]): boolean {
  for (let i = 0; i < candidate.length; i++) {
    if (candidate[i] !== current[i]) return candidate[i] > current[i]
  }
  return false
}

/**
 * The branch whose numbers represent a multi-branch selection: the worst one, so a
 * headline block never under-reports. Never a sum — the same CVE lives on every branch.
 */
export function highestRiskBranch(scansByBranch: Record<string, Scan>): string | null {
  let best: string | null = null
  let bestRank: number[] = []
  for (const branch of Object.keys(scansByBranch).sort()) {
    const candidate = severityRank(scansByBranch[branch])
    if (best === null || isHigher(candidate, bestRank)) {
      best = branch
      bestRank = candidate
    }
  }
  return best
}
