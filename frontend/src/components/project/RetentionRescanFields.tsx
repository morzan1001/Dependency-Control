import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import type { RetentionAction } from '@/types/project'
import type { AppConfig } from '@/types/system'

export const DEFAULT_RETENTION_DAYS = 90
export const DEFAULT_RESCAN_HOURS = 24

const RETENTION_OUTCOME: Record<RetentionAction, string> = { archive: 'archived to S3', none: 'kept forever', delete: 'deleted' }

export function ManagedGlobally({ children }: Readonly<{ children: string }>) {
  return (
    <div className="p-3 bg-muted rounded-md text-sm border">
      <p className="font-medium">Managed Globally</p>
      <p className="text-muted-foreground mt-1">{children}</p>
    </div>
  )
}

interface RetentionActionSelectProps {
  id: string
  value: RetentionAction
  onChange: (action: RetentionAction) => void
  archiveEnabled: boolean | undefined
}

export function RetentionActionSelect({ id, value, onChange, archiveEnabled }: Readonly<RetentionActionSelectProps>) {
  return (
    <Select value={value} onValueChange={(action) => onChange(action as RetentionAction)}>
      <SelectTrigger id={id}>
        <SelectValue placeholder="Select action" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="delete">Delete</SelectItem>
        {archiveEnabled && <SelectItem value="archive">Archive to S3</SelectItem>}
        <SelectItem value="none">None (Keep Forever)</SelectItem>
      </SelectContent>
    </Select>
  )
}

interface RetentionFieldsProps {
  days: number
  action: RetentionAction
  onChange: (retention: { retention_days?: number; retention_action?: RetentionAction }) => void
  appConfig: AppConfig | undefined
}

export function RetentionFields({ days, action, onChange, appConfig }: Readonly<RetentionFieldsProps>) {
  return (
    <div className="grid gap-2">
      <Label>Data Retention</Label>
      {appConfig?.retention_mode === 'global' ? (
        <ManagedGlobally>
          {appConfig.global_retention_days > 0
            ? `Data is retained for ${appConfig.global_retention_days} days (${RETENTION_OUTCOME[appConfig.global_retention_action || 'delete']}).`
            : 'Data retention is disabled (data is kept forever).'}
        </ManagedGlobally>
      ) : (
        <div className="border rounded-md p-4 space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="retention">Retention Period (Days)</Label>
            <Input
              id="retention"
              type="number"
              min="1"
              max="36500"
              value={days}
              onChange={(e) => onChange({ retention_days: Number.parseInt(e.target.value) || DEFAULT_RETENTION_DAYS })}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="retention-action">Retention Action</Label>
            <RetentionActionSelect
              id="retention-action"
              value={action}
              onChange={(retention_action) => onChange({ retention_action })}
              archiveEnabled={appConfig?.archive_enabled}
            />
            <p className="text-xs text-muted-foreground">
              Action to take when scan data exceeds the retention period.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

interface RescanFieldsProps {
  enabled: boolean
  interval: number
  onEnabledChange: (enabled: boolean) => void
  onIntervalChange: (hours: number) => void
  description: string
}

export function RescanFields({ enabled, interval, onEnabledChange, onIntervalChange, description }: Readonly<RescanFieldsProps>) {
  return (
    <div className="border rounded-md p-4 space-y-4">
      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <Label htmlFor="rescan-enabled" className="text-base">Enable Re-scanning</Label>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
        <Switch id="rescan-enabled" checked={enabled} onCheckedChange={onEnabledChange} />
      </div>
      {enabled && (
        <div className="grid gap-2">
          <Label htmlFor="rescan-interval">Interval (Hours)</Label>
          <Input
            id="rescan-interval"
            type="number"
            min="1"
            value={interval}
            onChange={(e) => onIntervalChange(Number.parseInt(e.target.value) || DEFAULT_RESCAN_HOURS)}
          />
          <p className="text-xs text-muted-foreground">How often to re-scan.</p>
        </div>
      )}
    </div>
  )
}
