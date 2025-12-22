import { useState, useMemo } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AnalyticsSummaryCards, SeverityDistribution, DependencyTypesChart } from '@/components/analytics/AnalyticsSummary'
import { DependencyStats } from '@/components/analytics/DependencyStats'
import { DependencyTree } from '@/components/analytics/DependencyTree'
import { ImpactAnalysis } from '@/components/analytics/ImpactAnalysis'
import { VulnerabilityHotspots } from '@/components/analytics/VulnerabilityHotspots'
import { CrossProjectSearch } from '@/components/analytics/CrossProjectSearch'
import { ComponentFindingsModal } from '@/components/analytics/ComponentFindingsModal'
import { BarChart3, Package, GitBranch, Zap, Flame, Search } from 'lucide-react'
import { useAuth } from '@/context/AuthContext'

export default function AnalyticsPage() {
  const [selectedComponent, setSelectedComponent] = useState<{ name: string; version?: string } | null>(null)
  const [showFindingsModal, setShowFindingsModal] = useState(false)
  const { hasPermission } = useAuth()

  // Check individual tab permissions
  const canViewSummary = hasPermission('analytics:read') || hasPermission('analytics:summary')
  const canViewDependencies = hasPermission('analytics:read') || hasPermission('analytics:dependencies')
  const canViewTree = hasPermission('analytics:read') || hasPermission('analytics:tree')
  const canViewImpact = hasPermission('analytics:read') || hasPermission('analytics:impact')
  const canViewHotspots = hasPermission('analytics:read') || hasPermission('analytics:hotspots')
  const canViewSearch = hasPermission('analytics:read') || hasPermission('analytics:search')

  // Determine available tabs
  const availableTabs = useMemo(() => {
    const tabs: { id: string; label: string; icon: typeof BarChart3 }[] = []
    if (canViewSummary) tabs.push({ id: 'overview', label: 'Overview', icon: BarChart3 })
    if (canViewDependencies) tabs.push({ id: 'dependencies', label: 'Dependencies', icon: Package })
    if (canViewTree) tabs.push({ id: 'tree', label: 'Tree', icon: GitBranch })
    if (canViewImpact) tabs.push({ id: 'impact', label: 'Impact', icon: Zap })
    if (canViewHotspots) tabs.push({ id: 'hotspots', label: 'Hotspots', icon: Flame })
    if (canViewSearch) tabs.push({ id: 'search', label: 'Search', icon: Search })
    return tabs
  }, [canViewSummary, canViewDependencies, canViewTree, canViewImpact, canViewHotspots, canViewSearch])

  const defaultTab = availableTabs.length > 0 ? availableTabs[0].id : 'overview'

  const handleComponentSelect = (name: string, version?: string) => {
    setSelectedComponent({ name, version })
    setShowFindingsModal(true)
  }

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Analytics</h2>
        <p className="text-muted-foreground">
          Analyze dependencies and vulnerabilities across all your projects.
        </p>
      </div>

      {/* Summary Cards - only show if user has summary permission */}
      {canViewSummary && <AnalyticsSummaryCards />}

      {/* Main Content Tabs */}
      <Tabs defaultValue={defaultTab} className="space-y-6">
        <TabsList className={`grid w-full lg:w-auto lg:inline-grid`} style={{ gridTemplateColumns: `repeat(${availableTabs.length}, minmax(0, 1fr))` }}>
          {availableTabs.map((tab) => {
            const Icon = tab.icon
            return (
              <TabsTrigger key={tab.id} value={tab.id} className="flex items-center gap-2">
                <Icon className="h-4 w-4" />
                <span className="hidden sm:inline">{tab.label}</span>
              </TabsTrigger>
            )
          })}
        </TabsList>

        {/* Overview Tab */}
        {canViewSummary && (
          <TabsContent value="overview" className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
              <SeverityDistribution />
              <DependencyTypesChart />
            </div>
            {canViewDependencies && (
              <DependencyStats 
                onSelectDependency={(dep) => handleComponentSelect(dep.name)}
              />
            )}
          </TabsContent>
        )}

        {/* Dependencies Tab */}
        {canViewDependencies && (
          <TabsContent value="dependencies">
            <DependencyStats 
              onSelectDependency={(dep) => handleComponentSelect(dep.name)}
            />
          </TabsContent>
        )}

        {/* Dependency Tree Tab */}
        {canViewTree && (
          <TabsContent value="tree">
            <DependencyTree 
              onSelectNode={(node) => handleComponentSelect(node.name, node.version)}
            />
          </TabsContent>
        )}

        {/* Impact Analysis Tab */}
        {canViewImpact && (
          <TabsContent value="impact">
            <ImpactAnalysis 
              onSelectComponent={(result) => handleComponentSelect(result.component, result.version)}
            />
          </TabsContent>
        )}

        {/* Vulnerability Hotspots Tab */}
        {canViewHotspots && (
          <TabsContent value="hotspots">
            <VulnerabilityHotspots 
              onSelectHotspot={(hotspot) => handleComponentSelect(hotspot.component, hotspot.version)}
            />
          </TabsContent>
        )}

        {/* Cross-Project Search Tab */}
        {canViewSearch && (
          <TabsContent value="search">
            <CrossProjectSearch 
              onSelectResult={(result) => handleComponentSelect(result.package, result.version)}
            />
          </TabsContent>
        )}
      </Tabs>

      {/* Component Findings Modal */}
      <ComponentFindingsModal
        component={selectedComponent?.name || ''}
        version={selectedComponent?.version}
        open={showFindingsModal}
        onOpenChange={setShowFindingsModal}
      />
    </div>
  )
}
