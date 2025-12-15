import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { createWaiver } from "@/lib/api"
import { toast } from "sonner"
import { ShieldAlert } from "lucide-react"
import { useAuth } from "@/context/AuthContext"

export interface Finding {
    id: string;
    title?: string;
    vuln_id?: string;
    severity?: string;
    type?: string;
    package?: string;
    pkg_name?: string;
    component?: string;
    version?: string;
    installed_version?: string;
    fixed_version?: string;
    description?: string;
    scanners?: string[];
    found_in?: string[];
    details?: any;
    [key: string]: any;
}

const getFindingTitle = (f: Finding) => f.title || f.vuln_id || f.id || "Finding Details";
const getFindingPackage = (f: Finding) => f.pkg_name || f.package || f.component || "Unknown";
const getFindingVersion = (f: Finding) => f.installed_version || f.version || "Unknown";
const getFindingId = (f: Finding) => f.vuln_id || f.id;

interface FindingDetailsModalProps {
    finding: Finding | null
    isOpen: boolean
    onClose: () => void
    projectId: string
}

export function FindingDetailsModal({ finding, isOpen, onClose, projectId }: FindingDetailsModalProps) {
    const [showWaiverForm, setShowWaiverForm] = useState(false)
    const { hasPermission } = useAuth()
    
    if (!finding) return null

    return (
        <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
            <DialogContent className="max-w-3xl max-h-[90vh] flex flex-col">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        {finding.severity && (
                            <Badge variant={
                                finding.severity === 'CRITICAL' ? 'destructive' :
                                finding.severity === 'HIGH' ? 'destructive' :
                                finding.severity === 'MEDIUM' ? 'default' : 'secondary'
                            }>
                                {finding.severity}
                            </Badge>
                        )}
                        <span className="truncate">{getFindingTitle(finding)}</span>
                    </DialogTitle>
                    <DialogDescription>
                        {finding.type} detected in {getFindingPackage(finding)}
                    </DialogDescription>
                </DialogHeader>

                <div className="flex-1 overflow-y-auto pr-4">
                    {showWaiverForm ? (
                        <WaiverForm 
                            finding={finding} 
                            projectId={projectId} 
                            onCancel={() => setShowWaiverForm(false)} 
                            onSuccess={() => {
                                setShowWaiverForm(false)
                                onClose()
                            }}
                        />
                    ) : (
                        <div className="space-y-6 py-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Component</h4>
                                    <p className="font-medium">{getFindingPackage(finding)}</p>
                                </div>
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Version</h4>
                                    <p className="font-medium">{getFindingVersion(finding)}</p>
                                </div>
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Fixed Version</h4>
                                    <p className="font-medium text-green-600">{finding.fixed_version || "None"}</p>
                                </div>
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">ID</h4>
                                    <p className="font-mono text-sm">{getFindingId(finding)}</p>
                                </div>
                                {finding.scanners && finding.scanners.length > 0 && (
                                    <div className="col-span-2">
                                        <h4 className="text-sm font-medium text-muted-foreground mb-1">Detected By</h4>
                                        <div className="flex flex-wrap gap-2">
                                            {finding.scanners.map((scanner) => (
                                                <Badge key={scanner} variant="outline" className="font-mono text-xs">
                                                    {scanner}
                                                </Badge>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                {finding.found_in && finding.found_in.length > 0 && (
                                    <div className="col-span-2">
                                        <h4 className="text-sm font-medium text-muted-foreground mb-1">Found In Sources</h4>
                                        <div className="flex flex-wrap gap-2">
                                            {finding.found_in.map((source) => (
                                                <Badge key={source} variant="secondary" className="font-mono text-xs">
                                                    {source}
                                                </Badge>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>

                            <div>
                                <h4 className="text-sm font-medium text-muted-foreground mb-2">Description</h4>
                                <p className="text-sm leading-relaxed">{finding.description || "No description available."}</p>
                            </div>

                            {finding.type === 'secret' && (
                                <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                                    <div>
                                        <h4 className="text-sm font-medium text-muted-foreground mb-1">Detector</h4>
                                        <p className="font-medium">{finding.details?.detector || "Unknown"}</p>
                                    </div>
                                    <div>
                                        <h4 className="text-sm font-medium text-muted-foreground mb-1">Verified</h4>
                                        <Badge variant={finding.details?.verified ? "destructive" : "secondary"}>
                                            {finding.details?.verified ? "Verified Live" : "Unverified"}
                                        </Badge>
                                    </div>
                                    {finding.details?.redacted && (
                                        <div className="col-span-2">
                                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Redacted Secret</h4>
                                            <code className="bg-background p-2 rounded border block w-full font-mono text-sm break-all">
                                                {finding.details.redacted}
                                            </code>
                                        </div>
                                    )}
                                </div>
                            )}

                            {finding.type === 'sast' && (
                                <div className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Rule ID</h4>
                                            <p className="font-mono text-sm">{finding.details?.check_id || "Unknown"}</p>
                                        </div>
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Location</h4>
                                            <p className="text-sm">
                                                Line {finding.details?.start?.line || "?"} - {finding.details?.end?.line || "?"}
                                            </p>
                                        </div>
                                    </div>
                                    {finding.details?.metadata && (
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-2">Rule Metadata</h4>
                                            <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs">
                                                {JSON.stringify(finding.details.metadata, null, 2)}
                                            </pre>
                                        </div>
                                    )}
                                </div>
                            )}

                            {finding.type === 'vulnerability' && (
                                <div className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-1">CVSS Score</h4>
                                            <div className="flex items-center gap-2">
                                                <span className={`text-lg font-bold ${
                                                    (finding.details?.cvss_score || 0) >= 9 ? 'text-red-600' :
                                                    (finding.details?.cvss_score || 0) >= 7 ? 'text-orange-600' :
                                                    (finding.details?.cvss_score || 0) >= 4 ? 'text-yellow-600' :
                                                    'text-blue-600'
                                                }`}>
                                                    {finding.details?.cvss_score || "N/A"}
                                                </span>
                                                {finding.details?.cvss_vector && (
                                                    <span className="text-xs text-muted-foreground font-mono bg-background px-1 rounded border">
                                                        {finding.details.cvss_vector}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Published</h4>
                                            <p className="text-sm">
                                                {finding.details?.published_date ? new Date(finding.details.published_date).toLocaleDateString() : "Unknown"}
                                            </p>
                                        </div>
                                    </div>

                                    {finding.details?.references && finding.details.references.length > 0 && (
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-2">References</h4>
                                            <div className="flex flex-col gap-1 max-h-[150px] overflow-y-auto text-sm">
                                                {finding.details.references.map((ref: string, i: number) => (
                                                    <a 
                                                        key={i} 
                                                        href={ref} 
                                                        target="_blank" 
                                                        rel="noopener noreferrer"
                                                        className="text-blue-600 hover:underline truncate"
                                                    >
                                                        {ref}
                                                    </a>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                    
                                    {finding.details?.urls && finding.details.urls.length > 0 && (
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-2">URLs</h4>
                                            <div className="flex flex-col gap-1 max-h-[150px] overflow-y-auto text-sm">
                                                {finding.details.urls.map((url: string, i: number) => (
                                                    <a 
                                                        key={i} 
                                                        href={url} 
                                                        target="_blank" 
                                                        rel="noopener noreferrer"
                                                        className="text-blue-600 hover:underline truncate"
                                                    >
                                                        {url}
                                                    </a>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {finding.details && finding.type !== 'secret' && finding.type !== 'sast' && finding.type !== 'vulnerability' && (
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-2">Additional Details</h4>
                                    <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs">
                                        {JSON.stringify(finding.details, null, 2)}
                                    </pre>
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {!showWaiverForm && (
                    <DialogFooter className="gap-2 sm:gap-0">
                        {hasPermission('waiver:manage') && (
                            <Button variant="outline" onClick={() => setShowWaiverForm(true)}>
                                <ShieldAlert className="mr-2 h-4 w-4" />
                                Create Waiver
                            </Button>
                        )}
                        <Button onClick={onClose}>Close</Button>
                    </DialogFooter>
                )}
            </DialogContent>
        </Dialog>
    )
}

function WaiverForm({ finding, projectId, onCancel, onSuccess }: { finding: Finding, projectId: string, onCancel: () => void, onSuccess: () => void }) {
    const [reason, setReason] = useState("")
    const [date, setDate] = useState("")
    const queryClient = useQueryClient()

    const createWaiverMutation = useMutation({
        mutationFn: createWaiver,
        onSuccess: () => {
            toast.success("Waiver created successfully")
            queryClient.invalidateQueries({ queryKey: ['waivers', projectId] })
            onSuccess()
        },
        onError: (error: any) => {
            toast.error("Failed to create waiver", {
                description: error.response?.data?.detail || "An error occurred"
            })
        }
    })

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault()
        if (!reason) return

        createWaiverMutation.mutate({
            project_id: projectId,
            finding_id: getFindingId(finding),
            package_name: getFindingPackage(finding),
            package_version: getFindingVersion(finding),
            finding_type: finding.type || "unknown",
            reason,
            expiration_date: date ? new Date(date).toISOString() : undefined
        })
    }

    return (
        <form onSubmit={handleSubmit} className="space-y-4 py-4">
            <div className="space-y-2">
                <Label>Reason for Waiver</Label>
                <textarea 
                    className="flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                    placeholder="Why is this finding being ignored? (e.g. False positive, Mitigating controls in place...)"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    required
                />
            </div>

            <div className="space-y-2 flex flex-col">
                <Label>Expiration Date (Optional)</Label>
                <Input 
                    type="date" 
                    value={date} 
                    onChange={(e) => setDate(e.target.value)} 
                    min={new Date().toISOString().split('T')[0]}
                />
                <p className="text-xs text-muted-foreground">
                    The waiver will automatically expire on this date.
                </p>
            </div>

            <div className="flex justify-end gap-2 pt-4">
                <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>
                <Button type="submit" disabled={createWaiverMutation.isPending}>
                    {createWaiverMutation.isPending && <span className="mr-2">Saving...</span>}
                    Confirm Waiver
                </Button>
            </div>
        </form>
    )
}
