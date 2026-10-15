import { Badge } from '@/components/ui/badge'
import type { TeamRef } from '@/types/team'

interface OwningTeamsCellProps {
  teams?: TeamRef[]
}

// Up to sixteen owners in a fixed-width column: the first is laid out, the rest are counted in the title.
export function OwningTeamsCell({ teams }: Readonly<OwningTeamsCellProps>) {
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
