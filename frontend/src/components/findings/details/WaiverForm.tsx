import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/utils'
import { ShieldAlert } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useCreateWaiver, waiverKeys } from '@/hooks/queries/use-waivers'
import { Finding } from '@/types/scan'
import { getFindingId, getFindingPackage, getFindingVersion } from './finding-details-helpers'

export function WaiverForm({
  finding,
  vulnId,
  projectId,
  onCancel,
  onSuccess,
}: {
  finding: Finding
  vulnId: string | null
  projectId: string
  onCancel: () => void
  onSuccess: () => void
}) {
  const [reason, setReason] = useState('')
  const [date, setDate] = useState('')
  const queryClient = useQueryClient()

  const createWaiverMutation = useCreateWaiver()

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!reason) return

    createWaiverMutation.mutate({
      project_id: projectId,
      finding_id: vulnId ? undefined : getFindingId(finding), // Only set finding_id if waiting whole finding
      vulnerability_id: vulnId || undefined, // Set vuln_id for specific cve waiver
      package_name: getFindingPackage(finding),
      package_version: getFindingVersion(finding),
      finding_type: finding.type || 'unknown',
      reason,
      expiration_date: date ? new Date(date).toISOString() : undefined,
    }, {
        onSuccess: () => {
            toast.success('Waiver created successfully')
            queryClient.invalidateQueries({ queryKey: waiverKeys.project(projectId) })
            onSuccess()
        },
        onError: (error) => {
            toast.error('Failed to create waiver', {
                description: getErrorMessage(error),
            })
        }
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4 py-4">
      {vulnId && (
        <div className="bg-blue-50 dark:bg-blue-950/50 p-3 rounded-md border border-blue-100 dark:border-blue-800 text-sm text-blue-800 dark:text-blue-300 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4" />
          Creating waiver specifically for <strong>{vulnId}</strong>
        </div>
      )}
      <div className="space-y-2">
        <Label>Reason for Waiver</Label>
        <Textarea
          className="min-h-[100px]"
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
        <p className="text-xs text-muted-foreground">The waiver will automatically expire on this date.</p>
      </div>

      <div className="flex justify-end gap-2 pt-4">
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={createWaiverMutation.isPending}>
          {createWaiverMutation.isPending ? 'Saving...' : 'Confirm Waiver'}
        </Button>
      </div>
    </form>
  )
}
