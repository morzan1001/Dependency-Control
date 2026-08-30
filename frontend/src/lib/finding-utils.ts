import { Container, FileCode, HardDrive, Layers, type LucideIcon } from 'lucide-react'
import type { ReachabilityInfo } from '@/types/scan'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE' | 'INFO' | 'UNKNOWN'

// Maps a CVE/GHSA id to its public advisory URL, or null if unknown.
export function advisoryUrl(id: string): string | null {
  if (id?.startsWith('CVE-')) return `https://nvd.nist.gov/vuln/detail/${id}`
  if (id?.startsWith('GHSA-')) return `https://github.com/advisories/${id}`
  return null
}

// Severity hex colours for charts (Recharts can't use Tailwind token classes);
// values mirror the light-mode severity tokens in index.css.
export const SEVERITY_CHART_COLORS: Record<Severity, string> = {
  CRITICAL: '#dc2626', // red-600 / --severity-critical
  HIGH: '#f97316', // orange-500 / --severity-high
  MEDIUM: '#eab308', // yellow-500 / --severity-medium
  LOW: '#3b82f6', // blue-500 / --severity-low
  NEGLIGIBLE: '#d1d5db', // gray-300
  INFO: '#6b7280', // gray-500 / --severity-info
  UNKNOWN: '#9ca3af', // gray-400
}

// Canonical severity ordering, most severe first.
export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'INFO', 'UNKNOWN']

export function getSeverityColor(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return 'text-severity-critical'
    case 'HIGH':
      return 'text-severity-high'
    case 'MEDIUM':
      return 'text-severity-medium'
    case 'LOW':
      return 'text-severity-low'
    case 'INFO':
      return 'text-severity-info'
    default:
      return 'text-muted-foreground'
  }
}

export function getSeverityBgColor(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return 'bg-severity-critical hover:bg-severity-critical'
    case 'HIGH':
      return 'bg-severity-high hover:bg-severity-high'
    case 'MEDIUM':
      return 'bg-severity-medium hover:bg-severity-medium'
    case 'LOW':
      return 'bg-severity-low hover:bg-severity-low'
    case 'INFO':
      return 'bg-severity-info hover:bg-severity-info'
    default:
      return 'bg-muted hover:bg-muted'
  }
}

export function getSeverityBadgeVariant(severity: string): 'destructive' | 'default' | 'secondary' | 'outline' {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 'destructive'
    case 'MEDIUM':
    case 'WARNING':
      return 'default'
    case 'LOW':
    case 'INFO':
      return 'secondary'
    default:
      return 'outline'
  }
}

export function getScoreColor(score: number): string {
  if (score < 3) return 'text-severity-critical'
  if (score < 5) return 'text-severity-high'
  if (score < 7) return 'text-severity-medium'
  return 'text-success'
}

// Colour for the backend 0-100 risk score (distinct from getScoreColor's 0-10 scorecard scale).
export function getRiskColorClass(score: number): string {
  if (score >= 70) return 'text-severity-critical'
  if (score >= 40) return 'text-severity-high'
  if (score >= 20) return 'text-severity-medium'
  return 'text-muted-foreground'
}

export function getScoreBorderColor(score: number): string {
  if (score < 3) return 'border-red-200 dark:border-red-800'
  if (score < 5) return 'border-amber-200 dark:border-amber-800'
  if (score < 7) return 'border-yellow-200 dark:border-yellow-800'
  return 'border-green-200 dark:border-green-800'
}

export function formatScorecardCriticalIssue(issue: string): string {
  switch (issue) {
    case 'Maintained':
      return 'Not Maintained'
    case 'Vulnerabilities':
      return 'Has Vulnerabilities'
    case 'Dangerous-Workflow':
      return 'Dangerous Workflow'
    default:
      return issue
  }
}

export function formatEpssScore(
  epss: number | undefined | null,
  decimals: number = 1,
  fallback: string | null = null
): string | null {
  if (epss === undefined || epss === null) return fallback
  return `${(epss * 100).toFixed(decimals)}%`
}

// Maps backend exploit_maturity to a text colour class; weaponized/active are
// real-world exploited (KEV) so they render as critical.
export function getExploitMaturityClass(maturity: string | null | undefined): string {
  if (maturity === 'weaponized' || maturity === 'active') return 'text-severity-critical font-medium';
  if (maturity === 'high') return 'text-severity-high';
  if (maturity === 'medium') return 'text-severity-medium';
  return '';
}

export type ReachabilityVerdict = 'reachable' | 'unreachable' | 'unknown'

// is_reachable is tri-state: only an explicit false means a callgraph covering the finding's
// ecosystem falsified it. Missing verdicts must never read as "not reachable".
export function getReachabilityDisplay(
  reachability: ReachabilityInfo
): { verdict: ReachabilityVerdict; label: string } {
  if (reachability.is_reachable === true) {
    const confirmed = reachability.analysis_level === 'symbol'
    return { verdict: 'reachable', label: confirmed ? 'Reachable (confirmed)' : 'Reachable (imported)' }
  }
  if (reachability.is_reachable === false) {
    return { verdict: 'unreachable', label: 'Not Reachable' }
  }
  return { verdict: 'unknown', label: 'Reachability unknown' }
}

export function getSecretTreeStatusInfo(
  inCurrentTree: boolean | null | undefined
): { label: string; className: string } | null {
  if (inCurrentTree === true) {
    return { label: 'In current code', className: 'bg-green-100 text-success' }
  }
  if (inCurrentTree === false) {
    return { label: 'Only in history', className: 'bg-amber-100 text-severity-medium' }
  }
  return null
}

interface SecretFindingLike {
  type?: string
  details?: { in_current_tree?: boolean | null; verified?: boolean }
}

// A deprioritized secret is unverified AND gone from the current tree; the backend lowers
// these to LOW severity. Mirrors calculate_secret_severity so the row de-emphasis matches
// the stored severity (and stays correct on pre-change scans, which keep CRITICAL).
export function isSecretDeprioritized(finding: SecretFindingLike): boolean {
  return (
    finding.type === 'secret' &&
    finding.details?.in_current_tree === false &&
    finding.details?.verified !== true
  )
}

// Remediation guidance keyed on tree state: a history-only secret cannot be cleared by deleting
// the current file — the credential must be rotated (verified ones are a live leak). Null for
// unknown tree state (no actionable, non-obvious advice to give).
export function getSecretRemediationHint(
  verified: boolean | null | undefined,
  inCurrentTree: boolean | null | undefined
): { text: string; tone: 'danger' | 'muted' } | null {
  if (inCurrentTree === false) {
    if (verified === true) {
      return {
        tone: 'danger',
        text: 'Live credential found only in git history. Deleting the file will not remove it — rotate this secret immediately.',
      }
    }
    return {
      tone: 'muted',
      text: 'This secret only exists in git history. Deleting the current file will not clear it — rotate the credential to be safe, then waive this finding to dismiss it.',
    }
  }
  if (inCurrentTree === true) {
    return { tone: 'muted', text: 'Remove the secret from the code and rotate the credential.' }
  }
  return null
}

export interface SourceInfo {
  icon: LucideIcon
  label: string
  color: string
  bgColor?: string
}

export function getSourceInfo(sourceType?: string): SourceInfo | null {
  switch (sourceType) {
    case 'image':
      return { 
        icon: Container, 
        label: 'Docker Image', 
        color: 'text-blue-500',
        bgColor: 'bg-blue-50 border-blue-200 dark:bg-blue-950/50 dark:border-blue-800'
      }
    case 'file':
      return { 
        icon: FileCode, 
        label: 'Source File', 
        color: 'text-green-500',
        bgColor: 'bg-green-50 border-green-200 dark:bg-green-950/50 dark:border-green-800'
      }
    case 'directory':
      return { 
        icon: HardDrive, 
        label: 'Directory', 
        color: 'text-amber-500',
        bgColor: 'bg-amber-50 border-amber-200 dark:bg-amber-950/50 dark:border-amber-800'
      }
    case 'application':
      return { 
        icon: Layers, 
        label: 'Application', 
        color: 'text-purple-500',
        bgColor: 'bg-purple-50 border-purple-200 dark:bg-purple-950/50 dark:border-purple-800'
      }
    default:
      return null
  }
}
