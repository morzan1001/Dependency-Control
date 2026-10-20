import { cn } from '@/lib/utils'

interface ThreatIntelNoteProps {
  sources: string[];
  consequence: string;
  className?: string;
}

export function ThreatIntelNote({ sources, consequence, className }: Readonly<ThreatIntelNoteProps>) {
  const names = [...new Set(sources)]
  if (names.length === 0) return null
  return (
    <div
      className={cn(
        'rounded border border-amber-400 bg-amber-50 p-2 text-xs text-amber-900 dark:bg-amber-950 dark:text-amber-200',
        className,
      )}
    >
      Live {names.join(' and ')} data could not be read in full; {consequence}
    </div>
  )
}
