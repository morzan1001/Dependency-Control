import { Badge } from "@/components/ui/badge"
import { ExternalLink, LucideIcon } from "lucide-react"

interface BadgeListProps {
    readonly items: string[]
    readonly variant?: "default" | "secondary" | "destructive" | "outline"
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
                const url = buildUrl?.(item)
                const badge = (
                    <Badge
                        key={item}
                        variant={variant}
                        className={`${url ? 'hover:bg-muted cursor-pointer' : ''} ${badgeClassName}`}
                    >
                        {Icon && <Icon className="h-3 w-3 mr-1" />}
                        {formatLabel ? formatLabel(item) : item}
                        {url && <ExternalLink className="h-3 w-3 ml-1" />}
                    </Badge>
                )

                if (url) {
                    return (
                        <a
                            key={item}
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
