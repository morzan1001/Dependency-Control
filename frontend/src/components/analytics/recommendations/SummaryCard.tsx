import { RecommendationsResponse } from '@/types/analytics'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { AlertTriangle, Lightbulb, ShieldAlert, type LucideIcon } from 'lucide-react'

interface Tile {
  label: string
  value: number
  color: string
}

const nonZero = (tiles: Tile[]) => tiles.filter((tile) => tile.value > 0)

function TileGroup({ title, icon: Icon, tiles }: Readonly<{ title: string; icon: LucideIcon; tiles: Tile[] }>) {
  if (tiles.length === 0) return null
  return (
    <div>
      <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
        <Icon className="h-4 w-4" />
        {title}
      </h4>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {tiles.map((tile) => (
          <div key={tile.label} className="text-center p-3 bg-muted rounded-lg">
            <div className={`text-2xl font-bold ${tile.color}`}>{tile.value}</div>
            <div className="text-xs text-muted-foreground">{tile.label}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

export function SummaryCard({ data }: Readonly<{ data: RecommendationsResponse }>) {
  const { summary } = data
  const healthTiles = nonZero([
    { label: 'Fragmentation', value: summary.fragmentation_issues ?? 0, color: 'text-violet-500' },
    { label: 'Trend Alerts', value: summary.trend_alerts ?? 0, color: 'text-rose-500' },
    { label: 'Cross-Project', value: summary.cross_project_issues ?? 0, color: 'text-sky-500' },
  ])
  const totalInsights = healthTiles.reduce((sum, tile) => sum + tile.value, 0)

  const insightsDescription =
    totalInsights > 0 ? `${totalInsights} dependency insights found` : 'No significant issues found';
  const summaryDescription =
    data.total_findings > 0
      ? `${data.total_findings} findings • ${totalInsights} dependency insights`
      : insightsDescription;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-lg">Recommendations Summary</CardTitle>
        <CardDescription>
          {summaryDescription}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {data.dependencies_read < data.dependencies_total && (
          <div className="rounded border border-amber-400 bg-amber-50 p-2 text-xs text-amber-900 dark:bg-amber-950 dark:text-amber-200">
            Reasoned over {data.dependencies_read.toLocaleString()} of {data.dependencies_total.toLocaleString()}{" "}
            dependency rows in this scan. Advice that counts components — fragmentation, license drift — is
            scoped to those rows and under-reports the rest.
          </div>
        )}
        <TileGroup
          title="Vulnerabilities"
          icon={ShieldAlert}
          tiles={data.total_vulnerabilities > 0 ? [
            { label: 'Fixable', value: summary.total_fixable_vulns, color: 'text-success' },
            { label: 'No Fix', value: summary.total_unfixable_vulns, color: 'text-gray-500' },
            { label: 'Image Updates', value: summary.base_image_updates, color: 'text-blue-500' },
            { label: 'Pkg Updates', value: summary.direct_updates + summary.transitive_updates, color: 'text-purple-500' },
          ] : []}
        />
        <TileGroup
          title="Other Security Findings"
          icon={AlertTriangle}
          tiles={nonZero([
            { label: 'Secrets', value: summary.secrets_to_rotate, color: 'text-destructive' },
            { label: 'SAST Issues', value: summary.sast_issues, color: 'text-cyan-500' },
            { label: 'IAC Issues', value: summary.iac_issues, color: 'text-indigo-500' },
            { label: 'License Issues', value: summary.license_issues, color: 'text-pink-500' },
          ])}
        />
        <TileGroup title="Health & Insights" icon={Lightbulb} tiles={healthTiles} />
      </CardContent>
    </Card>
  )
}
