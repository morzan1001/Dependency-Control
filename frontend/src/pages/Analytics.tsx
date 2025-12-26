import { useState, useMemo } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AnalyticsSummaryCards, SeverityDistribution, DependencyTypesChart } from '@/components/analytics/AnalyticsSummary'
import { DependencyStats } from '@/components/analytics/DependencyStats'
import { DependencyTree } from '@/components/analytics/DependencyTree'
import { ImpactAnalysis } from '@/components/analytics/ImpactAnalysis'
import { VulnerabilityHotspots } from '@/components/analytics/VulnerabilityHotspots'
import { CrossProjectSearch } from '@/components/analytics/CrossProjectSearch'
import { VulnerabilitySearch } from '@/components/analytics/VulnerabilitySearch'
import { Recommendations } from '@/components/analytics/Recommendations'
import { AnalyticsDependencyModal } from '@/components/analytics/AnalyticsDependencyModal'
import { BarChart3, GitBranch, Zap, Flame, Lightbulb, Package, ShieldAlert } from 'lucide-react'
import { useAuth } from '@/context/AuthContext'

export default function AnalyticsPage() {
  const [selectedComponent, setSelectedComponent] = useState<{ name: string; version?: string } | null>(null)
  const [showFindingsModal, setShowFindingsModal] = useState(false)
  const { hasPermission } = useAuth()

  // Check individual tab permissions
  const canViewSummary = hasPermission('analytics:read') || hasPermission('analytics:summary')
  const canViewTree = hasPermission('analytics:read') || hasPermission('analytics:tree')
  const canViewImpact = hasPermission('analytics:read') || hasPermission('analytics:impact')
  const canViewHotspots = hasPermission('analytics:read') || hasPermission('analytics:hotspots')
  const canViewSearch = hasPermission('analytics:read') || hasPermission('analytics:search')
  const canViewRecommendations = hasPermission('analytics:read') || hasPermission('analytics:recommendations')

  // Determine available tabs
  const availableTabs = useMemo(() => {
    const tabs: { id: string; label: string; icon: typeof BarChart3 }[] = []
    if (canViewSummary) tabs.push({ id: 'overview', label: 'Overview', icon: BarChart3 })
    if (canViewTree) tabs.push({ id: 'tree', label: 'Tree', icon: GitBranch })
    if (canViewImpact) tabs.push({ id: 'impact', label: 'Impact', icon: Zap })
    if (canViewHotspots) tabs.push({ id: 'hotspots', label: 'Hotspots', icon: Flame })
    if (canViewRecommendations) tabs.push({ id: 'recommendations', label: 'Recommendations', icon: Lightbulb })
    if (canViewSearch) tabs.push({ id: 'search-deps', label: 'Dependencies', icon: Package })
    if (canViewSearch) tabs.push({ id: 'search-vulns', label: 'Vulnerabilities', icon: ShieldAlert })
    return tabs
  }, [canViewSummary, canViewTree, canViewImpact, canViewHotspots, canViewRecommendations, canViewSearch])

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
        <TabsList>
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

        {/* Recommendations Tab */}
        {canViewRecommendations && (
          <TabsContent value="recommendations">
            <Recommendations />
          </TabsContent>
        )}

        {/* Cross-Project Dependency Search Tab */}
        {canViewSearch && (
          <TabsContent value="search-deps">
            <CrossProjectSearch 
              onSelectResult={(result) => handleComponentSelect(result.package, result.version)}
            />
          </TabsContent>
        )}

        {/* Vulnerability Search Tab */}
        {canViewSearch && (
          <TabsContent value="search-vulns">
            <VulnerabilitySearch />
          </TabsContent>
        )}
      </Tabs>

      {/* Component Details Modal */}
      <AnalyticsDependencyModal
        component={selectedComponent?.name || ''}
        version={selectedComponent?.version}
        open={showFindingsModal}
        onOpenChange={setShowFindingsModal}
      />
    </div>
  )
}
