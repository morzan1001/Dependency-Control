import { Badge } from '@/components/ui/badge'
import type { ReachabilityInfo } from '@/types/scan'

/** The sentence the reachability enrichment wrote, and the import sites it was drawn from. */
export function ReachabilityEvidence({ reachability }: { reachability: ReachabilityInfo }) {
    const shownLocations = reachability.import_locations ?? []
    const locationTotal = reachability.import_location_count ?? shownLocations.length
    return (
        <div className="w-full space-y-1">
            <p className="text-muted-foreground">{reachability.message}</p>
            {shownLocations.length > 0 && (
                <div className="flex flex-wrap items-center gap-1">
                    <span className="font-medium text-muted-foreground shrink-0">Imported at:</span>
                    {shownLocations.map((location) => (
                        <code key={location} className="text-xs bg-muted px-1.5 py-0.5 rounded">
                            {location}
                        </code>
                    ))}
                    {locationTotal > shownLocations.length && (
                        <Badge variant="secondary" className="text-[10px]">
                            showing {shownLocations.length} of {locationTotal}
                        </Badge>
                    )}
                </div>
            )}
        </div>
    )
}
