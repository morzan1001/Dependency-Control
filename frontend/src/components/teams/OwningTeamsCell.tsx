import { Badge } from '@/components/ui/badge'
import type { TeamRef } from '@/types/team'

interface OwningTeamsCellProps {
  teams?: TeamRef[]
}

// A project can be owned by up to sixteen teams and the cell holding them is a fixed-width column,
// so only the first name is laid out; the rest are counted and carried in the title, and the
// project's own settings list them in full.
export function OwningTeamsCell({ teams }: OwningTeamsCellProps) {
  const owners = teams ?? []

  if (owners.length === 0) {
    return <span className="text-muted-foreground">Unassigned</span>
  }

  const allNames = owners.map((team) => team.name).join(', ')

  return (
    <span className="flex min-w-0 items-center gap-1" title={allNames}>
      <span className="truncate">{owners[0].name}</span>
      {owners.length > 1 && (
        <Badge variant="secondary" className="shrink-0" aria-label={`${owners.length} owning teams: ${allNames}`}>
          +{owners.length - 1}
        </Badge>
      )}
    </span>
  )
}
