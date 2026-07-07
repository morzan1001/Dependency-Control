import { Badge } from "@/components/ui/badge"
import { ExternalLink, LucideIcon } from "lucide-react"

type BadgeVariant = "default" | "secondary" | "destructive" | "outline"

interface BadgeItem {
    label: string
    url?: string
    variant?: BadgeVariant
    className?: string
}

interface BadgeListProps {
    readonly items: (string | BadgeItem)[]
    readonly variant?: BadgeVariant
    readonly icon?: LucideIcon
    readonly buildUrl?: (item: string) => string
    readonly formatLabel?: (item: string) => string
    readonly badgeClassName?: string
}

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
