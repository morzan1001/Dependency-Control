/**
 * Shared UI State Components
 * 
 * Reusable components for loading, error, and empty states.
 * Eliminates duplicate skeleton/error/empty patterns across the application.
 */

import { AlertCircle, FileX, Inbox, RefreshCw, SearchX } from 'lucide-react'
import { Button } from './button'
import { Card, CardContent } from './card'
import { Skeleton } from './skeleton'

interface LoadingStateProps {
  message?: string
  className?: string
}

/**
 * Full-page loading spinner
 */
export function PageLoading({ message = 'Loading...', className = '' }: LoadingStateProps) {
  return (
    <div className={`flex flex-col items-center justify-center min-h-[400px] ${className}`}>
      <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      <p className="mt-4 text-muted-foreground">{message}</p>
    </div>
  )
}

interface SkeletonGridProps {
  rows?: number
  columns?: number
  className?: string
}

/**
 * Grid of skeleton cards for loading states
 */
export function SkeletonGrid({ rows = 3, columns = 1, className = '' }: SkeletonGridProps) {
  const gridCols = columns === 1 ? '' : columns === 2 ? 'md:grid-cols-2' : 'md:grid-cols-3'
  
  return (
    <div className={`grid gap-4 ${gridCols} ${className}`}>
      {Array(rows * columns).fill(0).map((_, i) => (
        <Card key={i}>
          <CardContent className="p-6">
            <Skeleton className="h-4 w-3/4 mb-2" />
            <Skeleton className="h-4 w-1/2" />
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

interface TableSkeletonProps {
  rows?: number
  columns?: number
  showHeader?: boolean
  className?: string
}

/**
 * Skeleton for table loading states
 */
export function TableSkeleton({ 
  rows = 5, 
  columns = 4, 
  showHeader = true,
  className = '' 
}: TableSkeletonProps) {
  return (
    <div className={`space-y-3 ${className}`}>
      {showHeader && (
        <div className="flex gap-4 pb-2 border-b">
          {Array(columns).fill(0).map((_, i) => (
            <Skeleton key={i} className="h-4 flex-1" />
          ))}
        </div>
      )}
      {Array(rows).fill(0).map((_, rowIdx) => (
        <div key={rowIdx} className="flex gap-4 py-2">
          {Array(columns).fill(0).map((_, colIdx) => (
            <Skeleton key={colIdx} className="h-4 flex-1" />
          ))}
        </div>
      ))}
    </div>
  )
}

interface CardSkeletonProps {
  showHeader?: boolean
  lines?: number
  className?: string
}

/**
 * Skeleton for card content
 */
export function CardSkeleton({ showHeader = true, lines = 3, className = '' }: CardSkeletonProps) {
  return (
    <Card className={className}>
      <CardContent className="p-6">
        {showHeader && <Skeleton className="h-6 w-1/3 mb-4" />}
        <div className="space-y-2">
          {Array(lines).fill(0).map((_, i) => (
            <Skeleton 
              key={i} 
              className={`h-4 ${i === lines - 1 ? 'w-2/3' : 'w-full'}`} 
            />
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

interface ErrorStateProps {
  title?: string
  message?: string
  onRetry?: () => void
  retryLabel?: string
  className?: string
}

/**
 * Error state with optional retry button
 */
export function ErrorState({
  title = 'Something went wrong',
  message = 'An error occurred while loading the data.',
  onRetry,
  retryLabel = 'Try again',
  className = '',
}: ErrorStateProps) {
  return (
    <div className={`flex flex-col items-center justify-center min-h-[200px] text-center p-6 ${className}`}>
      <AlertCircle className="h-12 w-12 text-destructive mb-4" />
      <h3 className="font-semibold text-lg mb-2">{title}</h3>
      <p className="text-muted-foreground mb-4 max-w-md">{message}</p>
      {onRetry && (
        <Button variant="outline" onClick={onRetry}>
          <RefreshCw className="h-4 w-4 mr-2" />
          {retryLabel}
        </Button>
      )}
    </div>
  )
}

/**
 * Inline error message (for form fields, etc.)
 */
export function InlineError({ message, className = '' }: { message: string; className?: string }) {
  return (
    <div className={`flex items-center gap-2 text-destructive text-sm ${className}`}>
      <AlertCircle className="h-4 w-4" />
      <span>{message}</span>
    </div>
  )
}

type EmptyStateVariant = 'default' | 'search' | 'data' | 'file'

interface EmptyStateProps {
  title?: string
  description?: string
  variant?: EmptyStateVariant
  action?: {
    label: string
    onClick: () => void
  }
  className?: string
}

const emptyStateIcons: Record<EmptyStateVariant, typeof Inbox> = {
  default: Inbox,
  search: SearchX,
  data: FileX,
  file: FileX,
}

/**
 * Empty state with icon and optional action
 */
export function EmptyState({
  title = 'No data found',
  description,
  variant = 'default',
  action,
  className = '',
}: EmptyStateProps) {
  const Icon = emptyStateIcons[variant]
  
  return (
    <div className={`flex flex-col items-center justify-center min-h-[200px] text-center p-6 ${className}`}>
      <Icon className="h-12 w-12 text-muted-foreground/50 mb-4" />
      <h3 className="font-semibold text-lg mb-1">{title}</h3>
      {description && (
        <p className="text-muted-foreground mb-4 max-w-md">{description}</p>
      )}
      {action && (
        <Button variant="outline" onClick={action.onClick}>
          {action.label}
        </Button>
      )}
    </div>
  )
}

/**
 * Empty search results
 */
export function NoSearchResults({ 
  query, 
  onClear,
  className = '' 
}: { 
  query?: string
  onClear?: () => void
  className?: string 
}) {
  return (
    <EmptyState
      variant="search"
      title="No results found"
      description={query ? `No results match "${query}"` : 'Try adjusting your search or filters'}
      action={onClear ? { label: 'Clear search', onClick: onClear } : undefined}
      className={className}
    />
  )
}

/**
 * No data available
 */
export function NoData({ 
  entityName = 'items',
  className = '' 
}: { 
  entityName?: string
  className?: string 
}) {
  return (
    <EmptyState
      variant="data"
      title={`No ${entityName} found`}
      description={`There are no ${entityName} to display yet.`}
      className={className}
    />
  )
}
