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

interface FindingDetailsModalProps {
    finding: any | null
    isOpen: boolean
    onClose: () => void
    projectId: string
}

export function FindingDetailsModal({ finding, isOpen, onClose, projectId }: FindingDetailsModalProps) {
    const [showWaiverForm, setShowWaiverForm] = useState(false)
    
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
                        <span className="truncate">{finding.title || finding.vuln_id || finding.id || "Finding Details"}</span>
                    </DialogTitle>
                    <DialogDescription>
                        {finding.type} detected in {finding.pkg_name || finding.package || finding.component}
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
                                    <p className="font-medium">{finding.pkg_name || finding.package || finding.component}</p>
                                </div>
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Version</h4>
                                    <p className="font-medium">{finding.installed_version || finding.version || "Unknown"}</p>
                                </div>
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Fixed Version</h4>
                                    <p className="font-medium text-green-600">{finding.fixed_version || "None"}</p>
                                </div>
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">ID</h4>
                                    <p className="font-mono text-sm">{finding.vuln_id || finding.id}</p>
                                </div>
                            </div>

                            <div>
                                <h4 className="text-sm font-medium text-muted-foreground mb-2">Description</h4>
                                <p className="text-sm leading-relaxed">{finding.description || "No description available."}</p>
                            </div>

                            {finding.details && (
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
                        <Button variant="outline" onClick={() => setShowWaiverForm(true)}>
                            <ShieldAlert className="mr-2 h-4 w-4" />
                            Create Waiver
                        </Button>
                        <Button onClick={onClose}>Close</Button>
                    </DialogFooter>
                )}
            </DialogContent>
        </Dialog>
    )
}

function WaiverForm({ finding, projectId, onCancel, onSuccess }: { finding: any, projectId: string, onCancel: () => void, onSuccess: () => void }) {
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
            finding_id: finding.vuln_id || finding.id,
            package_name: finding.pkg_name || finding.package || finding.component,
            package_version: finding.installed_version || finding.version,
            finding_type: finding.type,
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
