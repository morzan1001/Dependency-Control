import { Container, FileCode, HardDrive, Layers, type LucideIcon } from 'lucide-react'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN'

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

/**
 * Color class for a combined risk score on the backend's 0-100 scale
 * (CVSS impact + EPSS + KEV + reachability, per calculate_risk_score).
 * Distinct from getScoreColor, which is the inverted 0-10 OpenSSF scorecard.
 */
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

// Maps the backend exploit_maturity values (unknown/low/medium/high/active/
// weaponized — see backend scoring.calculate_exploit_maturity) to a text color
// class. weaponized/active are real-world exploited (KEV/ransomware) → critical.
export function getExploitMaturityClass(maturity: string | null | undefined): string {
  if (maturity === 'weaponized' || maturity === 'active') return 'text-severity-critical font-medium';
  if (maturity === 'high') return 'text-severity-high';
  if (maturity === 'medium') return 'text-severity-medium';
  return '';
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
