import { BranchInfo } from '@/types/project'
import { Scan } from '@/types/scan'

/** Exactly one branch: selecting every active one would count each finding once per branch. */
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

/** The worst branch stands in for a multi-branch selection; never a sum, the same CVE lives on every branch. */
export function highestRiskBranch(scansByBranch: Record<string, Scan>): string | null {
  let best: string | null = null
  let bestRank: number[] = []
  for (const branch of Object.keys(scansByBranch).sort((a, b) => a.localeCompare(b))) {
    const candidate = severityRank(scansByBranch[branch])
    if (best === null || isHigher(candidate, bestRank)) {
      best = branch
      bestRank = candidate
    }
  }
  return best
}
