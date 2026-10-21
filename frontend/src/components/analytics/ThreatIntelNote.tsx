import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export function Notice({ children, className }: Readonly<{ children: ReactNode; className?: string }>) {
  return (
    <div
      className={cn(
        'rounded border border-amber-400 bg-amber-50 p-2 text-xs text-amber-900 dark:bg-amber-950 dark:text-amber-200',
        className,
      )}
    >
      {children}
    </div>
  )
}

interface ThreatIntelNoteProps {
  sources: string[];
  consequence?: string;
  className?: string;
}

export function ThreatIntelNote({
  sources,
  consequence = 'exploit signals and the scores they raise may be incomplete.',
  className,
}: Readonly<ThreatIntelNoteProps>) {
  const names = [...new Set(sources)]
  if (names.length === 0) return null
  return (
    <Notice className={className}>
      Live {names.join(' and ')} data could not be read in full; {consequence}
    </Notice>
  )
}
