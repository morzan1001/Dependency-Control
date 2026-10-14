import type { ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

export function WarningHint({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <p className="text-xs text-amber-600 dark:text-amber-400 flex items-center gap-1">
      <AlertTriangle className="h-3 w-3" />
      {children}
    </p>
  )
}
