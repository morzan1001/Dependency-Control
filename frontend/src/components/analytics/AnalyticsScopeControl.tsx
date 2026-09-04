import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { useAnalyticsScope } from '@/hooks/queries/use-analytics'

const HEAD_MODE = '__head__'
const HEAD_MODE_LABEL = 'Latest scan'
const SCOPE_LABEL = 'Analytics scope'

interface AnalyticsScopeControlProps {
  releaseEnvironment?: string
  onChange: (releaseEnvironment: string | undefined) => void
}

export function AnalyticsScopeControl({ releaseEnvironment, onChange }: Readonly<AnalyticsScopeControlProps>) {
  const { data: scope } = useAnalyticsScope(releaseEnvironment)
  const environments = scope?.release_environments ?? []

  if (environments.length === 0) return null

  return (
    <Select
      value={releaseEnvironment ?? HEAD_MODE}
      onValueChange={(value) => onChange(value === HEAD_MODE ? undefined : value)}
    >
      <SelectTrigger className="w-[240px]" aria-label={SCOPE_LABEL}><SelectValue /></SelectTrigger>
      <SelectContent>
        <SelectItem value={HEAD_MODE}>{HEAD_MODE_LABEL}</SelectItem>
        {environments.map((environment) => (
          <SelectItem key={environment} value={environment}>{`${environment} release`}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
