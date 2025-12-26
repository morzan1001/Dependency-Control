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
  info: 'bg-blue-50 border-blue-200 text-blue-800 dark:bg-blue-950/50 dark:border-blue-800 dark:text-blue-300',
  warning: 'bg-amber-50 border-amber-200 text-amber-800 dark:bg-amber-950/50 dark:border-amber-800 dark:text-amber-300',
  danger: 'bg-red-50 border-red-200 text-red-800 dark:bg-red-950/50 dark:border-red-800 dark:text-red-300',
  success: 'bg-green-50 border-green-200 text-green-800 dark:bg-green-950/50 dark:border-green-800 dark:text-green-300',
}

const iconStyles: Record<BannerVariant, string> = {
  info: 'text-blue-500 dark:text-blue-400',
  warning: 'text-amber-500 dark:text-amber-400',
  danger: 'text-red-500 dark:text-red-400',
  success: 'text-green-500 dark:text-green-400',
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
