import { Badge } from "@/components/ui/badge"
import { getSeverityBadgeVariant } from "@/lib/finding-utils"

export function RiskBadge({ level }: Readonly<{ level: string }>) {
    return (
        <Badge variant={getSeverityBadgeVariant(level)}>
            {level.toUpperCase()}
        </Badge>
    )
}
