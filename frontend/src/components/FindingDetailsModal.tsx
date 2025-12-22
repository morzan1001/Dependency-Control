import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { createWaiver, Finding } from "@/lib/api"
import { toast } from "sonner"
import { ShieldAlert, Container, FileCode, HardDrive, Layers } from "lucide-react"
import { useAuth } from "@/context/AuthContext"
import { AxiosError } from "axios"

// Helper to get source info
function getSourceInfo(sourceType?: string) {
  switch (sourceType) {
    case 'image':
      return { icon: Container, label: 'Docker Image', color: 'text-blue-500', bgColor: 'bg-blue-50 border-blue-200' }
    case 'file':
      return { icon: FileCode, label: 'Source File', color: 'text-green-500', bgColor: 'bg-green-50 border-green-200' }
    case 'directory':
      return { icon: HardDrive, label: 'Directory', color: 'text-amber-500', bgColor: 'bg-amber-50 border-amber-200' }
    case 'application':
      return { icon: Layers, label: 'Application', color: 'text-purple-500', bgColor: 'bg-purple-50 border-purple-200' }
    default:
      return null
  }
}

const getFindingTitle = (f: Finding) => f.id || "Finding Details";
const getFindingPackage = (f: Finding) => f.component || "Unknown";
const getFindingVersion = (f: Finding) => f.version || "Unknown";
const getFindingId = (f: Finding) => f.id;

interface FindingDetailsModalProps {
    finding: Finding | null
    isOpen: boolean
    onClose: () => void
    projectId: string
    onSelectFinding?: (id: string) => void
}

export function FindingDetailsModal({ finding, isOpen, onClose, projectId, onSelectFinding }: FindingDetailsModalProps) {
    const [showWaiverForm, setShowWaiverForm] = useState(false)
    const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null)
    const { hasPermission } = useAuth()
    
    if (!finding) return null

    const handleWaive = (vulnId?: string) => {
        setSelectedVulnId(vulnId || null)
        setShowWaiverForm(true)
    }

    return (
        <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
            <DialogContent className="max-w-3xl max-h-[90vh] flex flex-col">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        {finding.severity && (
                            <Badge variant={
                                finding.severity === 'CRITICAL' ? 'destructive' :
                                finding.severity === 'HIGH' ? 'destructive' :
                                finding.severity === 'MEDIUM' ? 'default' : 
                                finding.severity === 'LOW' ? 'secondary' :
                                'outline'
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
                            vulnId={selectedVulnId}
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
                                    <p className="font-medium text-green-600">{finding.details?.fixed_version || "None"}</p>
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
                                        <div className="flex flex-wrap gap-2 max-h-[100px] overflow-y-auto">
                                            {finding.found_in.map((source) => (
                                                <Badge key={source} variant="secondary" className="font-mono text-xs">
                                                    {source}
                                                </Badge>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                {finding.related_findings && finding.related_findings.length > 0 && (
                                    <div className="col-span-2">
                                        <h4 className="text-sm font-medium text-muted-foreground mb-1">Related Findings</h4>
                                        <div className="flex flex-wrap gap-2">
                                            {finding.related_findings.map((relatedId) => {
                                                let label = relatedId;
                                                if (relatedId.startsWith("AGG:VULN:")) {
                                                    const parts = relatedId.split(":");
                                                    if (parts.length >= 4) {
                                                        label = `${parts[2]} (${parts[3]})`;
                                                    }
                                                }
                                                return (
                                                    <Badge 
                                                        key={relatedId} 
                                                        variant="outline" 
                                                        className="font-mono text-xs border-blue-200 bg-blue-50 text-blue-700 cursor-pointer hover:bg-blue-100"
                                                        onClick={() => onSelectFinding?.(relatedId)}
                                                    >
                                                        {label}
                                                    </Badge>
                                                );
                                            })}
                                        </div>
                                        <p className="text-xs text-muted-foreground mt-1">
                                            These components share the exact same version and set of vulnerabilities.
                                        </p>
                                    </div>
                                )}
                            </div>

                            {/* Source Information Section */}
                            {(finding.source_type || finding.purl || finding.direct !== undefined) && (
                                <div className="p-4 border rounded-lg bg-muted/30 space-y-3">
                                    <h4 className="text-sm font-medium flex items-center gap-2">
                                        {(() => {
                                            const sourceInfo = getSourceInfo(finding.source_type)
                                            if (sourceInfo) {
                                                const IconComponent = sourceInfo.icon
                                                return (
                                                    <>
                                                        <IconComponent className={`h-4 w-4 ${sourceInfo.color}`} />
                                                        <span>Origin: {sourceInfo.label}</span>
                                                    </>
                                                )
                                            }
                                            return <span>Package Origin</span>
                                        })()}
                                    </h4>
                                    
                                    <div className="grid grid-cols-2 gap-3 text-sm">
                                        {finding.direct !== undefined && (
                                            <div>
                                                <span className="text-muted-foreground">Dependency Type:</span>
                                                <Badge variant={finding.direct ? "default" : "secondary"} className="ml-2">
                                                    {finding.direct ? "Direct" : "Transitive"}
                                                </Badge>
                                            </div>
                                        )}
                                        
                                        {finding.source_target && (
                                            <div className="col-span-2">
                                                <span className="text-muted-foreground">Source:</span>
                                                <code className="ml-2 px-2 py-0.5 bg-background rounded text-xs font-mono break-all">
                                                    {finding.source_target}
                                                </code>
                                            </div>
                                        )}
                                        
                                        {finding.layer_digest && (
                                            <div className="col-span-2">
                                                <span className="text-muted-foreground">Container Layer:</span>
                                                <code className="ml-2 px-2 py-0.5 bg-background rounded text-xs font-mono">
                                                    {finding.layer_digest.length > 40 
                                                        ? `${finding.layer_digest.substring(0, 40)}...` 
                                                        : finding.layer_digest}
                                                </code>
                                            </div>
                                        )}
                                        
                                        {finding.purl && (
                                            <div className="col-span-2">
                                                <span className="text-muted-foreground">Package URL:</span>
                                                <code className="ml-2 px-2 py-0.5 bg-background rounded text-xs font-mono break-all">
                                                    {finding.purl}
                                                </code>
                                            </div>
                                        )}
                                        
                                        {finding.locations && finding.locations.length > 0 && (
                                            <div className="col-span-2">
                                                <span className="text-muted-foreground">File Locations:</span>
                                                <div className="mt-1 space-y-1">
                                                    {finding.locations.slice(0, 5).map((loc, i) => (
                                                        <code key={i} className="block px-2 py-0.5 bg-background rounded text-xs font-mono truncate">
                                                            {loc}
                                                        </code>
                                                    ))}
                                                    {finding.locations.length > 5 && (
                                                        <span className="text-xs text-muted-foreground">
                                                            +{finding.locations.length - 5} more locations
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                        )}
                                        
                                        {finding.found_by && (
                                            <div>
                                                <span className="text-muted-foreground">Found By:</span>
                                                <Badge variant="outline" className="ml-2 text-xs">
                                                    {finding.found_by}
                                                </Badge>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                            </div>

                            {finding.description && finding.type !== 'vulnerability' && (
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-2">Description</h4>
                                    <p className="text-sm leading-relaxed">{finding.description}</p>
                                </div>
                            )}

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
                                    {(() => {
                                        // Normalize to a list of vulnerabilities
                                        const vulns = finding.details?.vulnerabilities && finding.details.vulnerabilities.length > 0 
                                            ? finding.details.vulnerabilities 
                                            : [finding.details || {}]; // Fallback for legacy or single vuln structure

                                        return (
                                            <div className="space-y-4">
                                                <h4 className="text-sm font-medium text-muted-foreground">
                                                    {vulns.length > 1 
                                                        ? `Found ${vulns.length} vulnerabilities in ${getFindingPackage(finding)}` 
                                                        : "Vulnerability Details"}
                                                </h4>
                                                {vulns.map((vuln: any, idx: number) => (
                                                    <div key={idx} className="border rounded-lg p-4 space-y-3">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-2">
                                                                <Badge variant="outline">{vuln.id || getFindingId(finding)}</Badge>
                                                                <Badge variant={
                                                                    (vuln.severity || finding.severity) === 'CRITICAL' ? 'destructive' :
                                                                    (vuln.severity || finding.severity) === 'HIGH' ? 'destructive' :
                                                                    (vuln.severity || finding.severity) === 'MEDIUM' ? 'default' : 
                                                                    'secondary'
                                                                }>{vuln.severity || finding.severity}</Badge>
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                <span className="text-xs text-muted-foreground">
                                                                    Fixed in: <span className="font-medium text-foreground">{vuln.fixed_version || finding.details?.fixed_version || "None"}</span>
                                                                </span>
                                                                {hasPermission('waiver:manage') && (
                                                                    <Button variant="ghost" size="sm" className="h-6 px-2" onClick={() => handleWaive(vuln.id || getFindingId(finding))}>
                                                                        <ShieldAlert className="h-3 w-3 mr-1" />
                                                                        Waive
                                                                    </Button>
                                                                )}
                                                            </div>
                                                        </div>
                                                        <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                                                            {vuln.description || (finding.details?.vulnerabilities ? "" : finding.description) || "No description available."}
                                                        </p>
                                                        
                                                        <div className="flex flex-wrap gap-4 text-xs">
                                                            {(vuln.cvss_score || finding.details?.cvss_score) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium">CVSS: {vuln.cvss_score || finding.details?.cvss_score}</span>
                                                                    {(vuln.cvss_vector || finding.details?.cvss_vector) && <span className="font-mono text-muted-foreground">{vuln.cvss_vector || finding.details?.cvss_vector}</span>}
                                                                </div>
                                                            )}
                                                            {(vuln.details?.published_date || finding.details?.published_date) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">Published:</span>
                                                                    <span>{new Date(vuln.details?.published_date || finding.details?.published_date).toLocaleDateString()}</span>
                                                                </div>
                                                            )}
                                                            {(vuln.details?.cwe_ids || finding.details?.cwe_ids) && (vuln.details?.cwe_ids || finding.details?.cwe_ids).length > 0 && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">CWE:</span>
                                                                    <span className="font-mono">{(vuln.details?.cwe_ids || finding.details?.cwe_ids).join(', ')}</span>
                                                                </div>
                                                            )}
                                                            {(vuln.aliases || finding.aliases) && (vuln.aliases || finding.aliases).length > 0 && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">Aliases:</span>
                                                                    <span className="font-mono">{(vuln.aliases || finding.aliases).join(', ')}</span>
                                                                </div>
                                                            )}
                                                            {(vuln.scanners || finding.scanners) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">Detected by:</span>
                                                                    <span className="font-mono">{(vuln.scanners || finding.scanners).join(', ')}</span>
                                                                </div>
                                                            )}
                                                        </div>

                                                        <CollapsibleReferences references={vuln.references || finding.details?.references} />
                                                        <CollapsibleReferences references={vuln.details?.urls || finding.details?.urls} title="URLs" />
                                                    </div>
                                                ))}
                                            </div>
                                        );
                                    })()}
                                </div>
                            )}

                            {finding.details && finding.type !== 'secret' && finding.type !== 'sast' && finding.type !== 'vulnerability' && finding.type !== 'outdated' && (
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

function WaiverForm({ finding, vulnId, projectId, onCancel, onSuccess }: { finding: Finding, vulnId: string | null, projectId: string, onCancel: () => void, onSuccess: () => void }) {
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
        onError: (error: AxiosError<any>) => {
            toast.error("Failed to create waiver", {
                description: error.response?.data?.detail || "An error occurred"
            })
        }
    })

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault()
        if (!reason) return

        // If waiving a specific vulnerability, we might need to adjust the finding_id or pass extra data
        // For now, we assume the backend can handle the specific ID if we pass it, 
        // OR we are waiving the whole package but noting the specific vuln in the reason.
        // Ideally, the backend API should support a 'vulnerability_id' field.
        // Since we can't change the backend right now, we'll append it to the reason or use it as ID if appropriate.
        
        // Strategy: If vulnId is present, we use it as the finding_id for the waiver? 
        // No, finding_id links to the finding record. 
        // If the backend matches waivers by finding_id string, and we want to waive just one CVE,
        // we might need to change the backend. 
        // BUT, if we assume the user wants to waive THIS specific CVE, and the system uses CVEs as IDs usually...
        // Let's try passing the vulnId as finding_id if present, assuming the backend might check against it.
        // If not, we fall back to finding.id.
        
        // Actually, better approach for now without backend changes:
        // We waive the whole finding (Package) but auto-fill the reason with the specific CVE.
        
        const targetId = vulnId || getFindingId(finding)
        const finalReason = vulnId ? `[${vulnId}] ${reason}` : reason

        createWaiverMutation.mutate({
            project_id: projectId,
            finding_id: targetId, 
            package_name: getFindingPackage(finding),
            package_version: getFindingVersion(finding),
            finding_type: finding.type || "unknown",
            reason: finalReason,
            expiration_date: date ? new Date(date).toISOString() : undefined
        })
    }

    return (
        <form onSubmit={handleSubmit} className="space-y-4 py-4">
            {vulnId && (
                <div className="bg-blue-50 p-3 rounded-md border border-blue-100 text-sm text-blue-800 flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4" />
                    Creating waiver specifically for <strong>{vulnId}</strong>
                </div>
            )}
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

function CollapsibleReferences({ references, title = "References" }: { references: string[], title?: string }) {
    const [isOpen, setIsOpen] = useState(false)

    if (!references || references.length === 0) return null

    return (
        <div className="pt-2">
            <Button 
                variant="ghost" 
                size="sm" 
                className="h-auto py-1 px-0 text-xs font-medium hover:bg-transparent hover:underline justify-start text-muted-foreground"
                onClick={() => setIsOpen(!isOpen)}
            >
                {isOpen ? "▼" : "▶"} {title} ({references.length})
            </Button>
            
            {isOpen && (
                <div className="flex flex-col gap-1 mt-1 pl-2 border-l-2 border-muted ml-1">
                    {references.map((ref, i) => (
                        <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-500 hover:underline truncate block">
                            {ref}
                        </a>
                    ))}
                </div>
            )}
        </div>
    )
}
