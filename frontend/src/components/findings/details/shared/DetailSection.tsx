import { LucideIcon } from "lucide-react"
import { ReactNode } from "react"

interface DetailSectionProps {
    /** The label/title for this section */
    readonly label: string
    /** Optional icon - can be a LucideIcon component or a pre-rendered ReactNode */
    readonly icon?: LucideIcon | ReactNode
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
    icon, 
    children, 
    compact = false,
    className = ""
}: DetailSectionProps) {
    // Check if icon is a LucideIcon (function component) or a ReactNode (pre-rendered element)
    const isLucideIcon = typeof icon === 'function'
    
    return (
        <div className={className}>
            <h4 className={`text-sm font-medium text-muted-foreground ${compact ? 'mb-1' : 'mb-2'} ${icon ? 'flex items-center gap-1' : ''}`}>
                {icon && (isLucideIcon ? <>{(icon as LucideIcon)({ className: "h-3 w-3" })}</> : icon)}
                {label}
            </h4>
            {children}
        </div>
    )
}
