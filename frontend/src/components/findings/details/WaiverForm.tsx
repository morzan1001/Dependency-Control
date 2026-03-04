import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/utils'
import { ShieldAlert } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useCreateWaiver, waiverKeys } from '@/hooks/queries/use-waivers'
import { WaiverScope, WaiverStatus } from '@/types/waiver'
import { Finding } from '@/types/scan'
import { getFindingId, getFindingPackage, getFindingVersion } from './finding-details-helpers'

const SCOPE_TYPES = new Set(['sast', 'iac'])

function extractRuleId(finding: Finding): string | undefined {
  return finding.details?.rule_id || finding.details?.check_id || undefined
}

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
  const [scope, setScope] = useState<WaiverScope>('finding')
  const [status, setStatus] = useState<WaiverStatus>('accepted_risk')
  const queryClient = useQueryClient()

  const createWaiverMutation = useCreateWaiver()

  const supportsScopes = !vulnId && SCOPE_TYPES.has(finding.type ?? '')
  const ruleId = extractRuleId(finding)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!reason) return

    createWaiverMutation.mutate({
      project_id: projectId,
      finding_id: vulnId ? undefined : getFindingId(finding),
      vulnerability_id: vulnId || undefined,
      package_name: getFindingPackage(finding),
      package_version: getFindingVersion(finding),
      finding_type: finding.type || 'unknown',
      scope,
      rule_id: scope === 'rule' ? ruleId : undefined,
      reason,
      status,
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

      {supportsScopes && (
        <div className="rounded-md border p-3 space-y-3">
          <Label className="font-medium">Scope</Label>
          <RadioGroup value={scope} onValueChange={(v) => setScope(v as WaiverScope)}>
            <div className="flex items-start gap-3">
              <RadioGroupItem value="finding" id="scope-finding" className="mt-0.5" />
              <Label htmlFor="scope-finding" className="cursor-pointer font-normal">
                This finding only
              </Label>
            </div>
            <div className="flex items-start gap-3">
              <RadioGroupItem value="file" id="scope-file" className="mt-0.5" />
              <div>
                <Label htmlFor="scope-file" className="cursor-pointer font-normal">
                  All occurrences in <strong>{finding.component}</strong>
                </Label>
                <p className="text-xs text-muted-foreground">
                  Waives all findings of this rule in the same file.
                </p>
              </div>
            </div>
            {ruleId && (
              <div className="flex items-start gap-3">
                <RadioGroupItem value="rule" id="scope-rule" className="mt-0.5" />
                <div>
                  <Label htmlFor="scope-rule" className="cursor-pointer font-normal">
                    All occurrences in project
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    Waives rule <code className="bg-muted px-1 py-0.5 rounded text-[11px]">{ruleId}</code> across all files.
                  </p>
                </div>
              </div>
            )}
          </RadioGroup>
        </div>
      )}

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
