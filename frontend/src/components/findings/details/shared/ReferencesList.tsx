import { ExternalLink } from "lucide-react"

export function ReferencesList({ urls }: Readonly<{ urls: string[] }>) {
    if (!urls || urls.length === 0) return null

    return (
        <ul className="space-y-1">
            {urls.map((url) => (
                <li key={url} className="text-sm">
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
