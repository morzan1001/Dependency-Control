import { Badge } from "@/components/ui/badge"
import { getSeverityBadgeVariant } from "@/lib/finding-utils"

interface RiskBadgeProps {
    /** The risk level value */
    readonly level: string
    /** Show uppercase or as-is */
    readonly uppercase?: boolean
}

/**
 * Reusable badge for displaying risk/severity/confidence levels with consistent color coding.
 */
export function RiskBadge({ level, uppercase = true }: RiskBadgeProps) {
    const displayValue = uppercase ? level.toUpperCase() : level
    return (
        <Badge variant={getSeverityBadgeVariant(level)}>
            {displayValue}
        </Badge>
    )
}


