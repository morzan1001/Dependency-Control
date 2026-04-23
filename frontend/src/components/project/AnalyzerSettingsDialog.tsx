import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  AnalyzerSettingField,
  AnalyzerSettingsSchema,
} from '@/lib/analyzer-settings-schemas'

type SettingValue = string | number | boolean

interface AnalyzerSettingsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  schema: AnalyzerSettingsSchema
  /** Current values for this analyzer (from project.analyzer_settings[analyzer_id]). */
  currentValues: Record<string, unknown>
  /** Called when user clicks Save. Receives the full settings dict for this analyzer. */
  onSave: (values: Record<string, SettingValue>) => void
  isSaving?: boolean
  canEdit: boolean
}

export function AnalyzerSettingsDialog({
  open,
  onOpenChange,
  schema,
  currentValues,
  onSave,
  isSaving,
  canEdit,
}: Readonly<AnalyzerSettingsDialogProps>) {
  // Values are initialized lazily from the schema + currentValues the first
  // time the dialog mounts. To "reset" values when the dialog is reopened or
  // when the analyzer changes, the parent passes a `key` prop that forces a
  // remount (see ProjectSettings.tsx). Avoids the setState-in-effect anti-pattern:
  // https://react.dev/learn/you-might-not-need-an-effect
  const [values, setValues] = useState<Record<string, SettingValue>>(() =>
    initializeValues(schema, currentValues)
  )

  const handleChange = (key: string, value: SettingValue) => {
    setValues(prev => ({ ...prev, [key]: value }))
  }

  const handleSave = () => {
    onSave(values)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{schema.title}</DialogTitle>
          <DialogDescription>{schema.description}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          {schema.fields.map(field => (
            <FieldRenderer
              key={field.key}
              field={field}
              value={values[field.key]}
              onChange={(v) => handleChange(field.key, v)}
              disabled={!canEdit}
            />
          ))}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {canEdit && (
            <Button onClick={handleSave} disabled={isSaving}>
              {isSaving ? 'Saving...' : 'Save Settings'}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function initializeValues(
  schema: AnalyzerSettingsSchema,
  current: Record<string, unknown>
): Record<string, SettingValue> {
  const result: Record<string, SettingValue> = {}
  for (const field of schema.fields) {
    const existing = current[field.key]
    if (existing !== undefined && existing !== null) {
      result[field.key] = existing as SettingValue
    } else {
      result[field.key] = field.default
    }
  }
  return result
}

interface FieldRendererProps {
  field: AnalyzerSettingField
  value: SettingValue | undefined
  onChange: (value: SettingValue) => void
  disabled: boolean
}

function FieldRenderer({ field, value, onChange, disabled }: Readonly<FieldRendererProps>) {
  if (field.type === 'switch') {
    return (
      <div className="flex flex-row items-center justify-between rounded-lg border p-4">
        <div className="space-y-0.5 pr-4">
          <Label className="text-base">{field.label}</Label>
          {field.description && (
            <div className="text-sm text-muted-foreground">{field.description}</div>
          )}
        </div>
        <Switch
          checked={value === true}
          onCheckedChange={onChange}
          disabled={disabled}
        />
      </div>
    )
  }

  if (field.type === 'select') {
    return (
      <div className="space-y-2">
        <Label htmlFor={`field-${field.key}`}>{field.label}</Label>
        <Select
          value={value !== undefined ? String(value) : undefined}
          onValueChange={onChange}
          disabled={disabled}
        >
          <SelectTrigger id={`field-${field.key}`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {field.options?.map(opt => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {field.description && (
          <p className="text-xs text-muted-foreground">{field.description}</p>
        )}
      </div>
    )
  }

  // number / slider
  return (
    <div className="space-y-2">
      <Label htmlFor={`field-${field.key}`}>{field.label}</Label>
      <Input
        id={`field-${field.key}`}
        type="number"
        min={field.min}
        max={field.max}
        step={field.step}
        value={typeof value === 'number' ? value : Number(value ?? field.default)}
        onChange={(e) => {
          const num = Number.parseFloat(e.target.value)
          onChange(Number.isNaN(num) ? (field.default as number) : num)
        }}
        disabled={disabled}
      />
      {field.description && (
        <p className="text-xs text-muted-foreground">{field.description}</p>
      )}
    </div>
  )
}
