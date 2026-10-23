import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

const NOTICE_TONES = {
  warning: 'border-amber-400 bg-amber-50 text-amber-900 dark:bg-amber-950 dark:text-amber-200',
  info: 'border-blue-400 bg-blue-50 text-blue-900 dark:bg-blue-950 dark:text-blue-200',
}

export function Notice({
  children,
  className,
  tone = 'warning',
}: Readonly<{ children: ReactNode; className?: string; tone?: keyof typeof NOTICE_TONES }>) {
  return <div className={cn('rounded border p-2 text-xs', NOTICE_TONES[tone], className)}>{children}</div>
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
