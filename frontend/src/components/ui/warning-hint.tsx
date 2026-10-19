import type { ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

export function WarningHint({ id, children }: Readonly<{ id?: string; children: ReactNode }>) {
  return (
    <span id={id} className="flex items-start gap-1.5 text-xs text-muted-foreground">
      <AlertTriangle className="mt-px h-3 w-3 shrink-0 text-warning" />
      {children}
    </span>
  )
}
