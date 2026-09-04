import { useState, useMemo } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AnalyticsSummaryCards, SeverityDistribution, DependencyTypesChart } from '@/components/analytics/AnalyticsSummary'
import { AnalyticsScopeControl } from '@/components/analytics/AnalyticsScopeControl'
import { AnalyticsModeContext } from '@/context/analytics-mode'
import { DependencyStats } from '@/components/analytics/DependencyStats'
import { DependencyTree } from '@/components/analytics/DependencyTree'
import { ImpactAnalysis } from '@/components/analytics/ImpactAnalysis'
import { VulnerabilityHotspots } from '@/components/analytics/VulnerabilityHotspots'
import { CrossProjectSearch } from '@/components/analytics/CrossProjectSearch'
import { VulnerabilitySearch } from '@/components/analytics/VulnerabilitySearch'
import { Recommendations } from '@/components/analytics/Recommendations'
import { UpdateFrequency } from '@/components/analytics/UpdateFrequency'
import { UpdateFrequencyComparison } from '@/components/analytics/UpdateFrequencyComparison'
import { AnalyticsDependencyModal } from '@/components/analytics/AnalyticsDependencyModal'
import { BarChart3, GitBranch, Zap, Flame, Lightbulb, Package, ShieldAlert, RefreshCw, KeyRound } from 'lucide-react'
import { useAuth } from '@/context/useAuth'
import { CryptoAnalyticsTab } from '@/components/analytics/CryptoAnalyticsTab'

interface AnalyticsTab {
  id: string
  label: string
  icon: typeof BarChart3
  // True where every endpoint behind the tab accepts release_environment.
  readsRelease: boolean
}

export default function AnalyticsPage() {
  const [selectedComponent, setSelectedComponent] = useState<{ name: string; version?: string } | null>(null)
  const [showFindingsModal, setShowFindingsModal] = useState(false)
  // Undefined is head mode, the default every tab reports until the scope control names an environment.
  const [releaseEnvironment, setReleaseEnvironment] = useState<string | undefined>(undefined)
  const [pickedTab, setPickedTab] = useState<string | null>(null)
  const { hasPermission } = useAuth()

  const canViewSummary = hasPermission('analytics:read') || hasPermission('analytics:summary')
  const canViewTree = hasPermission('analytics:read') || hasPermission('analytics:tree')
  const canViewImpact = hasPermission('analytics:read') || hasPermission('analytics:impact')
  const canViewHotspots = hasPermission('analytics:read') || hasPermission('analytics:hotspots')
  const canViewSearch = hasPermission('analytics:read') || hasPermission('analytics:search')
  const canViewRecommendations = hasPermission('analytics:read') || hasPermission('analytics:recommendations')
  const canViewCrypto = hasPermission('analytics:read')

  const availableTabs = useMemo(() => {
    const tabs: AnalyticsTab[] = []
    if (canViewSummary) tabs.push({ id: 'overview', label: 'Overview', icon: BarChart3, readsRelease: true })
    if (canViewTree) tabs.push({ id: 'tree', label: 'Tree', icon: GitBranch, readsRelease: false })
    if (canViewImpact) tabs.push({ id: 'impact', label: 'Impact', icon: Zap, readsRelease: true })
    if (canViewHotspots) tabs.push({ id: 'hotspots', label: 'Hotspots', icon: Flame, readsRelease: true })
    if (canViewRecommendations) tabs.push({ id: 'recommendations', label: 'Recommendations', icon: Lightbulb, readsRelease: false })
    if (canViewRecommendations) tabs.push({ id: 'update-frequency', label: 'Update Frequency', icon: RefreshCw, readsRelease: false })
    if (canViewSearch) tabs.push({ id: 'search-deps', label: 'Dependencies', icon: Package, readsRelease: true })
    if (canViewSearch) tabs.push({ id: 'search-vulns', label: 'Vulnerabilities', icon: ShieldAlert, readsRelease: true })
    if (canViewCrypto) tabs.push({ id: 'cryptography', label: 'Cryptography', icon: KeyRound, readsRelease: false })
    return tabs
  }, [canViewSummary, canViewTree, canViewImpact, canViewHotspots, canViewRecommendations, canViewSearch, canViewCrypto])

  const defaultTab = availableTabs.length > 0 ? availableTabs[0].id : 'overview'
  const activeTab = pickedTab && availableTabs.some((tab) => tab.id === pickedTab) ? pickedTab : defaultTab
  const headOnlyTab = availableTabs.find((tab) => tab.id === activeTab && !tab.readsRelease)?.label

  // A head-only tab reports the branch tip whatever the switch says, so the page drops to head
  // there and the switch names what is on screen instead of a mode nothing below it obeys.
  const scopeEnvironment = headOnlyTab === undefined ? releaseEnvironment : undefined

  const handleComponentSelect = (name: string, version?: string) => {
    setSelectedComponent({ name, version })
    setShowFindingsModal(true)
  }

  return (
    <AnalyticsModeContext.Provider value={scopeEnvironment}>
      <div className="space-y-8">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Analytics</h2>
          <p className="text-muted-foreground">
            Analyze dependencies and vulnerabilities across all your projects.
          </p>
        </div>

        {/* Above the tabs, so the coverage caption stays on screen on the tabs that show no counters
            of their own — and outside the summary gate, whose permission not every tab implies. */}
        <AnalyticsScopeControl
          releaseEnvironment={scopeEnvironment}
          onChange={setReleaseEnvironment}
          headOnlyTab={headOnlyTab}
        />

        {canViewSummary && <AnalyticsSummaryCards />}

        <Tabs value={activeTab} onValueChange={setPickedTab} className="space-y-6">
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

          {canViewTree && (
            <TabsContent value="tree">
              <DependencyTree 
                onSelectNode={(node) => handleComponentSelect(node.name, node.version)}
              />
            </TabsContent>
          )}

          {canViewImpact && (
            <TabsContent value="impact">
              <ImpactAnalysis 
                onSelectComponent={(result) => handleComponentSelect(result.component, result.version)}
              />
            </TabsContent>
          )}

          {canViewHotspots && (
            <TabsContent value="hotspots">
              <VulnerabilityHotspots 
                onSelectHotspot={(hotspot) => handleComponentSelect(hotspot.component, hotspot.version)}
              />
            </TabsContent>
          )}

          {canViewRecommendations && (
            <TabsContent value="recommendations">
              <Recommendations />
            </TabsContent>
          )}

          {canViewRecommendations && (
            <TabsContent value="update-frequency" className="space-y-8">
              <UpdateFrequencyComparison />
              <div className="border-t pt-8">
                <UpdateFrequency />
              </div>
            </TabsContent>
          )}

          {canViewSearch && (
            <TabsContent value="search-deps">
              <CrossProjectSearch 
                onSelectResult={(result) => handleComponentSelect(result.package, result.version)}
              />
            </TabsContent>
          )}

          {canViewSearch && (
            <TabsContent value="search-vulns">
              <VulnerabilitySearch />
            </TabsContent>
          )}

          {canViewCrypto && (
            <TabsContent value="cryptography">
              <CryptoAnalyticsTab />
            </TabsContent>
          )}
        </Tabs>

        <AnalyticsDependencyModal
          component={selectedComponent?.name || ''}
          version={selectedComponent?.version}
          open={showFindingsModal}
          onOpenChange={setShowFindingsModal}
        />
      </div>
    </AnalyticsModeContext.Provider>
  )
}
