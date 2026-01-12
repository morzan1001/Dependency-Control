import { Badge } from "@/components/ui/badge"

type RiskLevel = "HIGH" | "MEDIUM" | "LOW" | "CRITICAL" | "INFO" | "UNKNOWN" | string

interface RiskBadgeProps {
    /** The risk level value */
    readonly level: RiskLevel
    /** Show uppercase or as-is */
    readonly uppercase?: boolean
}

/**
 * Get the appropriate badge variant based on risk level.
 */
function getRiskVariant(level: string): "destructive" | "default" | "secondary" | "outline" {
    const normalized = level.toUpperCase()
    switch (normalized) {
        case "CRITICAL":
        case "HIGH":
            return "destructive"
        case "MEDIUM":
        case "WARNING":
            return "default"
        case "LOW":
        case "INFO":
            return "secondary"
        default:
            return "outline"
    }
}

/**
 * Reusable badge for displaying risk/severity/confidence levels with consistent color coding.
 */
export function RiskBadge({ level, uppercase = true }: RiskBadgeProps) {
    const displayValue = uppercase ? level.toUpperCase() : level
    return (
        <Badge variant={getRiskVariant(level)}>
            {displayValue}
        </Badge>
    )
}


