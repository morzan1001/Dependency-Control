import { Shield, ShieldAlert } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import type { Finding } from "@/types/scan"
import { getSecretRemediationHint, getSecretTreeStatusInfo } from "@/lib/finding-utils"
import { formatDate, shortCommitHash } from "@/lib/utils"
import { DetailSection, FileLocation } from "./shared"
import type { ScanContext } from "./SastDetailsView"

interface SecretDetailsViewProps {
    readonly finding: Finding
    readonly scanContext?: ScanContext
}

export function SecretDetailsView({ finding, scanContext }: SecretDetailsViewProps) {
    const details = finding.details
    const hint = getSecretRemediationHint(details?.verified, details?.in_current_tree)
    const HintIcon = hint?.tone === 'danger' ? ShieldAlert : Shield
    const treeStatus = getSecretTreeStatusInfo(details?.in_current_tree)

    return (
        <div className="space-y-4">
            {scanContext && finding.component && (
                <FileLocation
                    filePath={finding.component}
                    startLine={details?.line}
                    scmContext={scanContext}
                />
            )}
            {hint && (
                <div className={`flex items-start gap-2 rounded-lg border p-3 text-sm ${hint.tone === 'danger'
                    ? 'bg-destructive/10 border-destructive/30 text-destructive'
                    : 'bg-muted/50 border-border text-muted-foreground'}`}>
                    <HintIcon className="h-4 w-4 mt-0.5 shrink-0" />
                    <p>{hint.text}</p>
                </div>
            )}
            <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                <DetailSection label="Detector" compact>
                    <p className="font-medium">{details?.detector_name || details?.detector || "Unknown"}</p>
                </DetailSection>
                <DetailSection label="Verified" compact>
                    <Badge variant={details?.verified ? "destructive" : "secondary"}>
                        {details?.verified ? "Verified Live" : "Unverified"}
                    </Badge>
                </DetailSection>
                {treeStatus && (
                    <DetailSection label="Tree Status" compact>
                        <Badge variant="outline" className={treeStatus.className}>
                            {treeStatus.label}
                        </Badge>
                    </DetailSection>
                )}
                {details?.commit && (
                    <DetailSection label="Origin Commit" compact>
                        <p className="font-mono text-xs">
                            {shortCommitHash(details.commit)}
                            {details.line && <span>:{details.line}</span>}
                        </p>
                        {details.commit_timestamp && (
                            <p className="text-xs text-muted-foreground mt-0.5">
                                {formatDate(details.commit_timestamp)}
                            </p>
                        )}
                    </DetailSection>
                )}
                {details?.redacted && (
                    <div className="col-span-2">
                        <DetailSection label="Redacted Secret" compact>
                            <code className="bg-background p-2 rounded border block w-full font-mono text-sm break-all">
                                {details.redacted}
                            </code>
                        </DetailSection>
                    </div>
                )}
            </div>
        </div>
    )
}
