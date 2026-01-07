import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { AxiosError } from 'axios'
import { toast } from 'sonner'
import { ShieldAlert } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useCreateWaiver, waiverKeys } from '@/hooks/queries/use-waivers'
import { Finding } from '@/types/scan'
import { getFindingId, getFindingPackage, getFindingVersion } from '@/components/findings/details/finding-details-helpers'

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

    // Use the new vulnerability_id field for granular CVE-level waivers
    // The backend now supports waiving specific vulnerabilities within aggregated findings
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
            // Check if it's an AxiosError to access response data
            const msg = (error instanceof AxiosError) 
                ? error.response?.data?.detail 
                : 'An error occurred';
                
            toast.error('Failed to create waiver', {
                description: typeof msg === 'string' ? msg : 'Unknown error',
            })
        }
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
        <p className="text-xs text-muted-foreground">The waiver will automatically expire on this date.</p>
      </div>

      <div className="flex justify-end gap-2 pt-4">
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={createWaiverMutation.isPending}>
          {createWaiverMutation.isPending && <span className="mr-2">Saving...</span>}
          Confirm Waiver
        </Button>
      </div>
    </form>
  )
}
