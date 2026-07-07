import { Badge } from "@/components/ui/badge"
import { getSeverityBadgeVariant } from "@/lib/finding-utils"

interface RiskBadgeProps {
    readonly level: string
    readonly uppercase?: boolean
}

export function RiskBadge({ level, uppercase = true }: RiskBadgeProps) {
    const displayValue = uppercase ? level.toUpperCase() : level
    return (
        <Badge variant={getSeverityBadgeVariant(level)}>
            {displayValue}
        </Badge>
    )
}
