import { useState } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AnalyticsSummaryCards, SeverityDistribution, DependencyTypesChart } from '@/components/analytics/AnalyticsSummary'
import { DependencyStats } from '@/components/analytics/DependencyStats'
import { DependencyTree } from '@/components/analytics/DependencyTree'
import { ImpactAnalysis } from '@/components/analytics/ImpactAnalysis'
import { VulnerabilityHotspots } from '@/components/analytics/VulnerabilityHotspots'
import { CrossProjectSearch } from '@/components/analytics/CrossProjectSearch'
import { ComponentFindingsModal } from '@/components/analytics/ComponentFindingsModal'
import { BarChart3, Package, GitBranch, Zap, Flame, Search } from 'lucide-react'

export default function AnalyticsPage() {
  const [selectedComponent, setSelectedComponent] = useState<{ name: string; version?: string } | null>(null)
  const [showFindingsModal, setShowFindingsModal] = useState(false)

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

      {/* Summary Cards */}
      <AnalyticsSummaryCards />

      {/* Main Content Tabs */}
      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList className="grid w-full grid-cols-6 lg:w-auto lg:inline-grid">
          <TabsTrigger value="overview" className="flex items-center gap-2">
            <BarChart3 className="h-4 w-4" />
            <span className="hidden sm:inline">Overview</span>
          </TabsTrigger>
          <TabsTrigger value="dependencies" className="flex items-center gap-2">
            <Package className="h-4 w-4" />
            <span className="hidden sm:inline">Dependencies</span>
          </TabsTrigger>
          <TabsTrigger value="tree" className="flex items-center gap-2">
            <GitBranch className="h-4 w-4" />
            <span className="hidden sm:inline">Tree</span>
          </TabsTrigger>
          <TabsTrigger value="impact" className="flex items-center gap-2">
            <Zap className="h-4 w-4" />
            <span className="hidden sm:inline">Impact</span>
          </TabsTrigger>
          <TabsTrigger value="hotspots" className="flex items-center gap-2">
            <Flame className="h-4 w-4" />
            <span className="hidden sm:inline">Hotspots</span>
          </TabsTrigger>
          <TabsTrigger value="search" className="flex items-center gap-2">
            <Search className="h-4 w-4" />
            <span className="hidden sm:inline">Search</span>
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2">
            <SeverityDistribution />
            <DependencyTypesChart />
          </div>
          <DependencyStats 
            onSelectDependency={(dep) => handleComponentSelect(dep.name)}
          />
        </TabsContent>

        {/* Dependencies Tab */}
        <TabsContent value="dependencies">
          <DependencyStats 
            onSelectDependency={(dep) => handleComponentSelect(dep.name)}
          />
        </TabsContent>

        {/* Dependency Tree Tab */}
        <TabsContent value="tree">
          <DependencyTree 
            onSelectNode={(node) => handleComponentSelect(node.name, node.version)}
          />
        </TabsContent>

        {/* Impact Analysis Tab */}
        <TabsContent value="impact">
          <ImpactAnalysis 
            onSelectComponent={(result) => handleComponentSelect(result.component, result.version)}
          />
        </TabsContent>

        {/* Vulnerability Hotspots Tab */}
        <TabsContent value="hotspots">
          <VulnerabilityHotspots 
            onSelectHotspot={(hotspot) => handleComponentSelect(hotspot.component, hotspot.version)}
          />
        </TabsContent>

        {/* Cross-Project Search Tab */}
        <TabsContent value="search">
          <CrossProjectSearch 
            onSelectResult={(result) => handleComponentSelect(result.package, result.version)}
          />
        </TabsContent>
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
