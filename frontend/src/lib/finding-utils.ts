/**
 * Shared utilities for findings, severity, and scores
 * Eliminates duplication across FindingsTable, FindingDetailsModal, analytics components
 */

// ============================================================================
// SEVERITY UTILITIES
// ============================================================================

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN'

/**
 * Severity sort order (higher = more severe)
 */
export const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
  UNKNOWN: 0,
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
}

/**
 * Chart/visualization colors for severity levels
 */
export const SEVERITY_CHART_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',  // red-500
  HIGH: '#f97316',      // orange-500
  MEDIUM: '#eab308',    // yellow-500
  LOW: '#3b82f6',       // blue-500
  INFO: '#6b7280',      // gray-500
  UNKNOWN: '#9ca3af',   // gray-400
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
  unknown: '#9ca3af',
}

/**
 * Sort items by severity (most severe first)
 */
export function sortBySeverity<T>(items: T[], getSeverity: (item: T) => string): T[] {
  return [...items].sort((a, b) => {
    const aVal = SEVERITY_ORDER[getSeverity(a)] ?? 0
    const bVal = SEVERITY_ORDER[getSeverity(b)] ?? 0
    return bVal - aVal
  })
}

/**
 * Get Tailwind color class for severity level (text color)
 */
export function getSeverityColor(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return 'text-red-600 dark:text-red-400'
    case 'HIGH':
      return 'text-orange-600 dark:text-orange-400'
    case 'MEDIUM':
      return 'text-yellow-600 dark:text-yellow-400'
    case 'LOW':
      return 'text-blue-600 dark:text-blue-400'
    case 'INFO':
      return 'text-gray-600 dark:text-gray-400'
    default:
      return 'text-gray-500 dark:text-gray-400'
  }
}

/**
 * Get Tailwind background color class for severity level
 */
export function getSeverityBgColor(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return 'bg-red-500 hover:bg-red-600'
    case 'HIGH':
      return 'bg-orange-500 hover:bg-orange-600'
    case 'MEDIUM':
      return 'bg-yellow-500 hover:bg-yellow-600 text-black'
    case 'LOW':
      return 'bg-blue-500 hover:bg-blue-600'
    case 'INFO':
      return 'bg-gray-500 hover:bg-gray-600'
    default:
      return 'bg-gray-400 hover:bg-gray-500'
  }
}

/**
 * Get shadcn Badge variant for severity level
 */
export function getSeverityBadgeVariant(severity: string): 'destructive' | 'default' | 'secondary' | 'outline' {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 'destructive'
    case 'MEDIUM':
      return 'default'
    case 'LOW':
      return 'secondary'
    default:
      return 'outline'
  }
}

/**
 * Get border color class for severity (used in cards/panels)
 */
export function getSeverityBorderColor(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return 'border-l-red-500'
    case 'HIGH':
      return 'border-l-orange-500'
    case 'MEDIUM':
      return 'border-l-yellow-500'
    case 'LOW':
      return 'border-l-blue-500'
    default:
      return 'border-l-transparent'
  }
}

// ============================================================================
// SCORE UTILITIES (OpenSSF Scorecard, etc.)
// ============================================================================

/**
 * Get color class for a score (0-10 scale)
 */
export function getScoreColor(score: number): string {
  if (score < 3) return 'text-red-600 dark:text-red-400'
  if (score < 5) return 'text-amber-600 dark:text-amber-400'
  if (score < 7) return 'text-yellow-600 dark:text-yellow-400'
  return 'text-green-600 dark:text-green-400'
}

/**
 * Get background color class for a score (0-10 scale)
 */
export function getScoreBgColor(score: number): string {
  if (score < 3) return 'bg-red-100 dark:bg-red-900/30'
  if (score < 5) return 'bg-amber-100 dark:bg-amber-900/30'
  if (score < 7) return 'bg-yellow-100 dark:bg-yellow-900/30'
  return 'bg-green-100 dark:bg-green-900/30'
}

// ============================================================================
// EPSS UTILITIES
// ============================================================================

/**
 * Format EPSS score as percentage
 */
export function formatEpssScore(epss: number | undefined | null): string {
  if (epss === undefined || epss === null) return 'N/A'
  return `${(epss * 100).toFixed(2)}%`
}

/**
 * Get color class for EPSS score
 */
export function getEpssColor(epss: number | undefined | null): string {
  if (epss === undefined || epss === null) return 'text-muted-foreground'
  if (epss >= 0.1) return 'text-red-600 dark:text-red-400'
  if (epss >= 0.05) return 'text-orange-600 dark:text-orange-400'
  if (epss >= 0.01) return 'text-yellow-600 dark:text-yellow-400'
  return 'text-green-600 dark:text-green-400'
}

/**
 * Check if EPSS is considered high risk (>=10%)
 */
export function isHighEpss(epss: number | undefined | null): boolean {
  return epss !== undefined && epss !== null && epss >= 0.1
}

// ============================================================================
// DATE UTILITIES
// ============================================================================

/**
 * Format date consistently across the application
 */
export function formatDate(
  date: string | Date | undefined | null,
  options: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'short', day: 'numeric' }
): string {
  if (!date) return 'N/A'
  try {
    const d = typeof date === 'string' ? new Date(date) : date
    if (isNaN(d.getTime())) return String(date)
    return d.toLocaleDateString(undefined, options)
  } catch {
    return String(date)
  }
}

/**
 * Format date with time
 */
export function formatDateTime(date: string | Date | undefined | null): string {
  return formatDate(date, { 
    year: 'numeric', 
    month: 'short', 
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

// ============================================================================
// FINDING TYPE UTILITIES
// ============================================================================

export interface FindingTypeBadgeStyle {
  borderColor: string
  bgColor: string
  textColor: string
}

/**
 * Get styling for finding type badges
 */
export function getFindingTypeBadgeStyle(type: string): FindingTypeBadgeStyle {
  switch (type?.toLowerCase()) {
    case 'outdated':
      return {
        borderColor: 'border-blue-200 dark:border-blue-800',
        bgColor: 'bg-blue-50 dark:bg-blue-950/50',
        textColor: 'text-blue-700 dark:text-blue-300'
      }
    case 'quality':
      return {
        borderColor: 'border-yellow-200 dark:border-yellow-800',
        bgColor: 'bg-yellow-50 dark:bg-yellow-950/50',
        textColor: 'text-yellow-700 dark:text-yellow-300'
      }
    case 'license':
      return {
        borderColor: 'border-purple-200 dark:border-purple-800',
        bgColor: 'bg-purple-50 dark:bg-purple-950/50',
        textColor: 'text-purple-700 dark:text-purple-300'
      }
    case 'eol':
      return {
        borderColor: 'border-orange-200 dark:border-orange-800',
        bgColor: 'bg-orange-50 dark:bg-orange-950/50',
        textColor: 'text-orange-700 dark:text-orange-300'
      }
    case 'vulnerability':
      return {
        borderColor: 'border-red-200 dark:border-red-800',
        bgColor: 'bg-red-50 dark:bg-red-950/50',
        textColor: 'text-red-700 dark:text-red-300'
      }
    case 'secret':
      return {
        borderColor: 'border-pink-200 dark:border-pink-800',
        bgColor: 'bg-pink-50 dark:bg-pink-950/50',
        textColor: 'text-pink-700 dark:text-pink-300'
      }
    case 'sast':
      return {
        borderColor: 'border-indigo-200 dark:border-indigo-800',
        bgColor: 'bg-indigo-50 dark:bg-indigo-950/50',
        textColor: 'text-indigo-700 dark:text-indigo-300'
      }
    default:
      return {
        borderColor: 'border-gray-200 dark:border-gray-700',
        bgColor: 'bg-gray-50 dark:bg-gray-800/50',
        textColor: 'text-gray-700 dark:text-gray-300'
      }
  }
}

// ============================================================================
// SOURCE INFO UTILITIES
// ============================================================================

import { Container, FileCode, HardDrive, Layers, type LucideIcon } from 'lucide-react'

export interface SourceInfo {
  icon: LucideIcon
  label: string
  color: string
  bgColor?: string
}

/**
 * Get source info based on source type
 */
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
