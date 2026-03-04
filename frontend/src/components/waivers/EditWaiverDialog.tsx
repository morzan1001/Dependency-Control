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
import { useUpdateWaiver } from '@/hooks/queries/use-waivers'
import { Waiver, WaiverStatus } from '@/types/waiver'

interface EditWaiverDialogProps {
    waiver: Waiver | null
    open: boolean
    onOpenChange: (open: boolean) => void
}

function EditWaiverForm({ waiver, onClose }: { waiver: Waiver; onClose: () => void }) {
    const [reason, setReason] = useState(waiver.reason)
    const [status, setStatus] = useState<WaiverStatus>(waiver.status || 'accepted_risk')
    const [date, setDate] = useState(waiver.expiration_date ? waiver.expiration_date.split('T')[0] : '')

    const updateMutation = useUpdateWaiver()

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault()
        if (!reason) return

        updateMutation.mutate({
            waiverId: waiver.id,
            data: {
                reason,
                status,
                expiration_date: date ? new Date(date).toISOString() : null,
            },
        }, {
            onSuccess: () => {
                toast.success('Waiver updated successfully')
                onClose()
            },
            onError: (error) => {
                toast.error('Failed to update waiver', {
                    description: getErrorMessage(error),
                })
            },
        })
    }

    return (
        <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
                <Label>Reason</Label>
                <Textarea
                    className="min-h-[100px]"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    required
                />
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
                <Button type="button" variant="outline" onClick={onClose}>
                    Cancel
                </Button>
                <Button type="submit" disabled={updateMutation.isPending}>
                    {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
                </Button>
            </DialogFooter>
        </form>
    )
}

export function EditWaiverDialog({ waiver, open, onOpenChange }: EditWaiverDialogProps) {
    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Edit Waiver</DialogTitle>
                    <DialogDescription>
                        Update the waiver for <strong>{waiver?.package_name}</strong>
                        {waiver?.finding_id && <> ({waiver.finding_id})</>}
                    </DialogDescription>
                </DialogHeader>
                {waiver && open && (
                    <EditWaiverForm
                        key={waiver.id}
                        waiver={waiver}
                        onClose={() => onOpenChange(false)}
                    />
                )}
            </DialogContent>
        </Dialog>
    )
}
