import { Badge } from "@/components/ui/badge"
import { ExternalLink, LucideIcon } from "lucide-react"

type BadgeVariant = "default" | "secondary" | "destructive" | "outline"

interface BadgeItem {
    /** The text to display */
    label: string
    /** Optional URL to make the badge a link */
    url?: string
    /** Custom variant override */
    variant?: BadgeVariant
    /** Custom class for styling */
    className?: string
}

interface BadgeListProps {
    /** Array of items to render as badges */
    readonly items: (string | BadgeItem)[]
    /** Default variant for all badges */
    readonly variant?: BadgeVariant
    /** Optional icon to show before each badge label */
    readonly icon?: LucideIcon
    /** URL builder function for simple string items */
    readonly buildUrl?: (item: string) => string
    /** Label transformer for simple string items */
    readonly formatLabel?: (item: string) => string
    /** Custom className for badges */
    readonly badgeClassName?: string
}

/**
 * Reusable badge list component for displaying tags, categories, references, etc.
 */
export function BadgeList({ 
    items, 
    variant = "secondary", 
    icon: Icon,
    buildUrl,
    formatLabel,
    badgeClassName = ""
}: BadgeListProps) {
    if (!items || items.length === 0) return null

    return (
        <div className="flex flex-wrap gap-2">
            {items.map((item) => {
                const isSimple = typeof item === 'string'
                const simpleLabel = formatLabel ? formatLabel(item as string) : (item as string)
                const label = isSimple ? simpleLabel : item.label
                const simpleUrl = buildUrl ? buildUrl(item as string) : undefined
                const url = isSimple ? simpleUrl : item.url
                const itemVariant = isSimple ? variant : (item.variant || variant)
                const itemClassName = isSimple ? badgeClassName : (item.className || badgeClassName)
                const itemKey = isSimple ? (item as string) : item.label

                const badge = (
                    <Badge
                        key={itemKey}
                        variant={itemVariant}
                        className={`${url ? 'hover:bg-muted cursor-pointer' : ''} ${itemClassName}`}
                    >
                        {Icon && <Icon className="h-3 w-3 mr-1" />}
                        {label}
                        {url && <ExternalLink className="h-3 w-3 ml-1" />}
                    </Badge>
                )

                if (url) {
                    return (
                        <a
                            key={itemKey}
                            href={url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center"
                        >
                            {badge}
                        </a>
                    )
                }

                return badge
            })}
        </div>
    )
}
