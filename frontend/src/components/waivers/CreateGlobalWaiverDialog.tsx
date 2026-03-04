import { useState } from 'react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/utils'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog'
import { useCreateWaiver } from '@/hooks/queries/use-waivers'
import { WaiverScope, WaiverStatus } from '@/types/waiver'
import { FindingType } from '@/types/scan'

const FINDING_TYPES = [
    { value: 'vulnerability', label: 'Vulnerability' },
    { value: 'license', label: 'License' },
    { value: 'secret', label: 'Secret' },
    { value: 'malware', label: 'Malware' },
    { value: 'eol', label: 'End of Life' },
    { value: 'iac', label: 'Infrastructure as Code' },
    { value: 'sast', label: 'SAST' },
    { value: 'outdated', label: 'Outdated' },
    { value: 'quality', label: 'Quality' },
    { value: 'other', label: 'Other' },
] as const

interface CreateGlobalWaiverDialogProps {
    open: boolean
    onOpenChange: (open: boolean) => void
}

export function CreateGlobalWaiverDialog({ open, onOpenChange }: CreateGlobalWaiverDialogProps) {
    const [findingId, setFindingId] = useState('')
    const [packageName, setPackageName] = useState('')
    const [packageVersion, setPackageVersion] = useState('')
    const [findingType, setFindingType] = useState<FindingType | ''>('')
    const [scope, setScope] = useState<WaiverScope>('finding')
    const [ruleId, setRuleId] = useState('')
    const [status, setStatus] = useState<WaiverStatus>('accepted_risk')
    const [reason, setReason] = useState('')
    const [date, setDate] = useState('')

    const createMutation = useCreateWaiver()

    const resetForm = () => {
        setFindingId('')
        setPackageName('')
        setPackageVersion('')
        setFindingType('')
        setScope('finding')
        setRuleId('')
        setStatus('accepted_risk')
        setReason('')
        setDate('')
    }

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault()
        if (!reason) return

        createMutation.mutate({
            // No project_id → global waiver
            finding_id: findingId || undefined,
            package_name: packageName || undefined,
            package_version: packageVersion || undefined,
            finding_type: findingType || undefined,
            scope,
            rule_id: scope === 'rule' && ruleId ? ruleId : undefined,
            status,
            reason,
            expiration_date: date ? new Date(date).toISOString() : undefined,
        }, {
            onSuccess: () => {
                toast.success('Global waiver created successfully')
                resetForm()
                onOpenChange(false)
            },
            onError: (error) => {
                toast.error('Failed to create global waiver', {
                    description: getErrorMessage(error),
                })
            },
        })
    }

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="max-w-lg">
                <DialogHeader>
                    <DialogTitle>Create Global Waiver</DialogTitle>
                    <DialogDescription>
                        Global waivers apply across all projects. Leave optional fields empty to match broadly.
                    </DialogDescription>
                </DialogHeader>
                <form onSubmit={handleSubmit} className="space-y-4 max-h-[60vh] overflow-y-auto pr-1">
                    <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                            <Label>Finding ID</Label>
                            <Input
                                placeholder="e.g. CVE-2023-1234"
                                value={findingId}
                                onChange={(e) => setFindingId(e.target.value)}
                            />
                        </div>
                        <div className="space-y-2">
                            <Label>Finding Type</Label>
                            <Select value={findingType} onValueChange={(v) => setFindingType(v as FindingType | '')}>
                                <SelectTrigger>
                                    <SelectValue placeholder="Any" />
                                </SelectTrigger>
                                <SelectContent>
                                    {FINDING_TYPES.map((t) => (
                                        <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                            <Label>Package Name</Label>
                            <Input
                                placeholder="e.g. lodash"
                                value={packageName}
                                onChange={(e) => setPackageName(e.target.value)}
                            />
                        </div>
                        <div className="space-y-2">
                            <Label>Package Version</Label>
                            <Input
                                placeholder="e.g. 4.17.21"
                                value={packageVersion}
                                onChange={(e) => setPackageVersion(e.target.value)}
                            />
                        </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                            <Label>Scope</Label>
                            <Select value={scope} onValueChange={(v) => setScope(v as WaiverScope)}>
                                <SelectTrigger>
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="finding">Finding (exact match)</SelectItem>
                                    <SelectItem value="file">File (same rule in file)</SelectItem>
                                    <SelectItem value="rule">Rule (project-wide)</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="space-y-2">
                            <Label>Status</Label>
                            <Select value={status} onValueChange={(v) => setStatus(v as WaiverStatus)}>
                                <SelectTrigger>
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="accepted_risk">Accepted Risk</SelectItem>
                                    <SelectItem value="false_positive">False Positive</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </div>

                    {scope === 'rule' && (
                        <div className="space-y-2">
                            <Label>Rule ID</Label>
                            <Input
                                placeholder="e.g. javascript_lang_insufficiently_random_values"
                                value={ruleId}
                                onChange={(e) => setRuleId(e.target.value)}
                            />
                        </div>
                    )}

                    <div className="space-y-2">
                        <Label>Reason</Label>
                        <Textarea
                            className="min-h-[80px]"
                            placeholder="Why is this finding being waived globally?"
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
                    </div>

                    <DialogFooter>
                        <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                            Cancel
                        </Button>
                        <Button type="submit" disabled={createMutation.isPending}>
                            {createMutation.isPending ? 'Creating...' : 'Create Global Waiver'}
                        </Button>
                    </DialogFooter>
                </form>
            </DialogContent>
        </Dialog>
    )
}
