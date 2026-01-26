/**
 * Reusable ContextBanner component
 * Displays contextual information with consistent styling (info, warning, danger, success)
 */

import React from 'react'

export type BannerVariant = 'info' | 'warning' | 'danger' | 'success'

export interface ContextBannerProps {
  icon: React.ElementType
  title: string
  children: React.ReactNode
  variant: BannerVariant
  action?: React.ReactNode
}

const variantStyles: Record<BannerVariant, string> = {
  info: 'bg-muted/30 border-blue-200 text-foreground dark:bg-muted/20 dark:border-blue-800',
  warning: 'bg-muted/30 border-amber-200 text-foreground dark:bg-muted/20 dark:border-amber-800',
  danger: 'bg-muted/30 border-red-200 text-foreground dark:bg-muted/20 dark:border-red-800',
  success: 'bg-muted/30 border-green-200 text-foreground dark:bg-muted/20 dark:border-green-800',
}

const iconStyles: Record<BannerVariant, string> = {
  info: 'text-info',
  warning: 'text-warning',
  danger: 'text-destructive',
  success: 'text-success',
}

export function ContextBanner({ icon: Icon, title, children, variant, action }: ContextBannerProps) {
  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg border ${variantStyles[variant]}`}>
      <Icon className={`h-4 w-4 mt-0.5 flex-shrink-0 ${iconStyles[variant]}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <span className="text-sm font-medium">{title}</span>
          {action}
        </div>
        <div className="text-sm opacity-90 mt-0.5">{children}</div>
      </div>
    </div>
  )
}

/**
 * Compact inline alert style
 */
export function ContextAlert({ 
  icon: Icon, 
  children, 
  variant 
}: { 
  icon: React.ElementType
  children: React.ReactNode
  variant: BannerVariant 
}) {
  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-sm ${variantStyles[variant]}`}>
      <Icon className={`h-4 w-4 ${iconStyles[variant]}`} />
      <span>{children}</span>
    </div>
  )
}
