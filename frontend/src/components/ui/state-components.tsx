/**
 * Shared UI State Components
 * 
 * Reusable components for loading, error, and empty states.
 * Eliminates duplicate skeleton/error/empty patterns across the application.
 */

import { AlertCircle, FileX, Inbox, SearchX } from 'lucide-react'
import { Button } from './button'

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
