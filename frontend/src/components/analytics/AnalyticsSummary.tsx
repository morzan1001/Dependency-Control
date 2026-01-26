import { useAnalyticsSummary } from '@/hooks/queries/use-analytics'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Package, AlertTriangle, Layers, PieChart } from 'lucide-react'

export function AnalyticsSummaryCards() {
  const { data: summary, isLoading } = useAnalyticsSummary()

  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {Array(4).fill(0).map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-xl" />
        ))}
      </div>
    )
  }

  const stats = [
    {
      title: "Total Dependencies",
      value: summary?.total_dependencies.toLocaleString() || "0",
      icon: Package,
      description: "Across all projects"
    },
    {
      title: "Unique Packages",
      value: summary?.unique_packages.toLocaleString() || "0",
      icon: Layers,
      description: "Distinct libraries"
    },
    {
      title: "Total Vulnerabilities",
      value: summary?.total_vulnerabilities.toLocaleString() || "0",
      icon: AlertTriangle,
      description: "Across all projects",
      className: summary?.total_vulnerabilities && summary.total_vulnerabilities > 0 ? "text-destructive" : ""
    },
    {
      title: "Package Types",
      value: summary?.dependency_types.length.toString() || "0",
      icon: PieChart,
      description: "npm, pypi, maven, etc."
    }
  ]

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {stats.map((stat) => {
        const Icon = stat.icon
        return (
          <Card key={stat.title}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
              <Icon className={`h-4 w-4 text-muted-foreground ${stat.className || ''}`} />
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${stat.className || ''}`}>{stat.value}</div>
              <p className="text-xs text-muted-foreground">{stat.description}</p>
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}

export function SeverityDistribution() {
  const { data: summary, isLoading } = useAnalyticsSummary()

  if (isLoading) {
    return <Skeleton className="h-40 w-full" />
  }

  const severity = summary?.severity_distribution
  if (!severity) return null

  const total = severity.critical + severity.high + severity.medium + severity.low
  if (total === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Severity Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground text-center py-4">No vulnerabilities found</p>
        </CardContent>
      </Card>
    )
  }

  const severities = [
    { label: 'Critical', value: severity.critical, color: 'bg-severity-critical' },
    { label: 'High', value: severity.high, color: 'bg-severity-high' },
    { label: 'Medium', value: severity.medium, color: 'bg-severity-medium' },
    { label: 'Low', value: severity.low, color: 'bg-severity-low' },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Severity Distribution</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Stacked bar */}
        <div className="flex h-4 rounded-full overflow-hidden">
          {severities.map((s) => (
            s.value > 0 && (
              <div
                key={s.label}
                className={`${s.color}`}
                style={{ width: `${(s.value / total) * 100}%` }}
                title={`${s.label}: ${s.value}`}
              />
            )
          ))}
        </div>
        
        {/* Legend */}
        <div className="grid grid-cols-2 gap-2">
          {severities.map((s) => (
            <div key={s.label} className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${s.color}`} />
              <span className="text-sm text-muted-foreground">{s.label}</span>
              <span className="text-sm font-medium ml-auto">{s.value}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

export function DependencyTypesChart() {
  const { data: summary, isLoading } = useAnalyticsSummary()

  if (isLoading) {
    return <Skeleton className="h-40 w-full" />
  }

  const types = summary?.dependency_types || []
  if (types.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Dependency Types</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground text-center py-4">No dependencies found</p>
        </CardContent>
      </Card>
    )
  }

  const colors = [
    'bg-blue-500',
    'bg-green-500',
    'bg-purple-500',
    'bg-orange-500',
    'bg-pink-500',
    'bg-cyan-500',
    'bg-yellow-500',
    'bg-red-500',
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Dependency Types</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {types.slice(0, 8).map((t, i) => (
          <div key={t.type} className="space-y-1">
            <div className="flex justify-between text-sm">
              <span className="font-medium">{t.type}</span>
              <span className="text-muted-foreground">{t.count} ({t.percentage}%)</span>
            </div>
            <div className="h-2 bg-secondary rounded-full overflow-hidden">
              <div
                className={`h-full ${colors[i % colors.length]}`}
                style={{ width: `${t.percentage}%` }}
              />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
