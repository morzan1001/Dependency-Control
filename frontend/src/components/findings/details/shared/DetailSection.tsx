import { LucideIcon } from "lucide-react"
import { ReactNode } from "react"

interface DetailSectionProps {
    /** The label/title for this section */
    readonly label: string
    /** Optional Lucide icon component */
    readonly icon?: LucideIcon
    /** The content to display */
    readonly children: ReactNode
    /** Use mb-1 (tight) or mb-2 (normal) spacing. Default: normal */
    readonly compact?: boolean
    /** Additional className for the container */
    readonly className?: string
}

/**
 * Reusable detail section with consistent label styling.
 * Used across all finding detail views.
 */
export function DetailSection({
    label,
    icon: Icon,
    children,
    compact = false,
    className = ""
}: DetailSectionProps) {
    return (
        <div className={className}>
            <h4 className={`text-sm font-medium text-muted-foreground ${compact ? 'mb-1' : 'mb-2'} ${Icon ? 'flex items-center gap-1' : ''}`}>
                {Icon && <Icon className="h-3 w-3" />}
                {label}
            </h4>
            {children}
        </div>
    )
}
