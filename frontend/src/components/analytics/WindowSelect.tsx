import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

const WINDOW_OPTIONS = [
  { value: '30', label: 'Last 30 days' },
  { value: '90', label: 'Last 90 days' },
  { value: '365', label: 'Last 12 months' },
  { value: 'scans', label: 'Last 20 scans' },
]

export function WindowSelect({
  value,
  onChange,
}: Readonly<{ value: number | undefined; onChange: (v: number | undefined) => void }>) {
  return (
    <Select
      value={value === undefined ? 'scans' : String(value)}
      onValueChange={(v) => onChange(v === 'scans' ? undefined : Number(v))}
    >
      <SelectTrigger className="w-[180px]">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {WINDOW_OPTIONS.map((opt) => (
          <SelectItem key={opt.value} value={opt.value}>
            {opt.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
