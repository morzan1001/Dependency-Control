import { ExternalLink } from "lucide-react"

interface ReferencesListProps {
    /** Array of URLs to display */
    readonly urls: string[]
    /** Use compact (smaller text) styling */
    readonly compact?: boolean
}

/**
 * Reusable component for displaying a list of clickable reference links.
 */
export function ReferencesList({ urls, compact = false }: ReferencesListProps) {
    if (!urls || urls.length === 0) return null

    return (
        <ul className="space-y-1">
            {urls.map((url, idx) => (
                <li key={idx} className={compact ? "text-xs" : "text-sm"}>
                    <a
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:underline inline-flex items-center gap-1"
                    >
                        <ExternalLink className="h-3 w-3 flex-shrink-0" />
                        <span className="break-all">{url}</span>
                    </a>
                </li>
            ))}
        </ul>
    )
}
