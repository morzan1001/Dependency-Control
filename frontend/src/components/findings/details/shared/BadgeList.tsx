import { Badge } from "@/components/ui/badge"
import { AlertTriangle, LucideIcon } from "lucide-react"
import { AdvisoryLink } from "../../AdvisoryLink"

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
                const label = formatLabel ? formatLabel(item) : item
                if (buildUrl) {
                    return <AdvisoryLink key={item} id={item} href={buildUrl(item)} variant={variant} label={label} icon={Icon} className={badgeClassName} />
                }
                return (
                    <Badge key={item} variant={variant} className={badgeClassName}>
                        {Icon && <Icon className="h-3 w-3 mr-1" />}
                        {label}
                    </Badge>
                )
            })}
        </div>
    )
}

// Stored Trivy advisories may still carry the CWE- prefix the other scanners never write.
export function CweBadgeList({ ids }: Readonly<{ ids: string[] }>) {
    return (
        <BadgeList
            items={ids.map((id) => id.replace(/^CWE-/i, ""))}
            variant="outline"
            icon={AlertTriangle}
            formatLabel={(cwe) => `CWE-${cwe}`}
            buildUrl={(cwe) => `https://cwe.mitre.org/data/definitions/${cwe}.html`}
        />
    )
}
