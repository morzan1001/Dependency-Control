import { LucideIcon } from "lucide-react"
import { ReactNode } from "react"

interface DetailSectionProps {
    readonly label: string
    readonly icon?: LucideIcon
    readonly children: ReactNode
    readonly compact?: boolean
    readonly className?: string
}

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
