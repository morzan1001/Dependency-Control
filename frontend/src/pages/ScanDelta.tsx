import { useCallback, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { FindingsDeltaTab } from '@/components/scans/delta/tabs/FindingsDeltaTab'
import { ComponentsDeltaTab } from '@/components/scans/delta/tabs/ComponentsDeltaTab'
import { CryptoDeltaTab } from '@/components/scans/delta/tabs/CryptoDeltaTab'
import { DeltaBadge } from '@/components/scans/delta/shared/DeltaBadge'
import { DeltaHeader } from '@/components/scans/delta/DeltaHeader'

type TabId = 'findings' | 'components' | 'crypto'
const TAB_IDS: TabId[] = ['findings', 'components', 'crypto']

export default function ScanDelta() {
  const { id } = useParams<{ id: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const from = searchParams.get('from')
  const to = searchParams.get('to')
  const tabParam = searchParams.get('tab')
  const tab: TabId = TAB_IDS.includes(tabParam as TabId) ? (tabParam as TabId) : 'findings'

  const [visited, setVisited] = useState<Set<TabId>>(new Set([tab]))
  const [counts, setCounts] = useState<Record<TabId, number | null>>({
    findings: null, components: null, crypto: null,
  })

  const onCount = useCallback((tabId: TabId, n: number) => {
    setCounts((prev) => (prev[tabId] === n ? prev : { ...prev, [tabId]: n }))
  }, [])

  if (!id || !from || !to || from === to) {
    return (
      <div className="container mx-auto py-10">
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-12">
            <p className="font-medium">Invalid scan comparison</p>
            <p className="text-sm text-muted-foreground">Pick two different scans from the Pipelines tab.</p>
            <Button asChild variant="outline">
              <Link to={id ? `/projects/${id}` : '/dashboard'}>Back to project</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  const setParams = (next: Record<string, string>) => {
    const params = new URLSearchParams(searchParams)
    for (const [key, value] of Object.entries(next)) params.set(key, value)
    setSearchParams(params, { replace: true })
  }

  const onTabChange = (value: string) => {
    const tabId = value as TabId
    setVisited((prev) => new Set(prev).add(tabId))
    setParams({ tab: tabId })
  }

  const onPairChange = (nextFrom: string, nextTo: string) => {
    setVisited(new Set<TabId>([tab]))
    setCounts({ findings: null, components: null, crypto: null })
    setParams({ from: nextFrom, to: nextTo })
  }

  return (
    <div className="container mx-auto space-y-6 py-10">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link to={`/projects/${id}`}><ArrowLeft className="h-4 w-4" /></Link>
        </Button>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Scan delta</h1>
          <p className="text-muted-foreground">Added, removed, and changed entries between two scans.</p>
        </div>
      </div>

      <DeltaHeader projectId={id} fromScanId={from} toScanId={to} onChange={onPairChange} />

      {/* key remounts tab bodies on pair change so filters/pagination reset */}
      <Tabs key={`${from}->${to}`} value={tab} onValueChange={onTabChange} className="space-y-4">
        <TabsList>
          <TabsTrigger value="findings">Findings <DeltaBadge count={counts.findings} /></TabsTrigger>
          <TabsTrigger value="components">Components <DeltaBadge count={counts.components} /></TabsTrigger>
          <TabsTrigger value="crypto">Crypto <DeltaBadge count={counts.crypto} /></TabsTrigger>
        </TabsList>
        <TabsContent value="findings">
          {visited.has('findings') && (
            <FindingsDeltaTab projectId={id} fromScanId={from} toScanId={to}
              onCountLoaded={(n) => onCount('findings', n)} />
          )}
        </TabsContent>
        <TabsContent value="components">
          {visited.has('components') && (
            <ComponentsDeltaTab projectId={id} fromScanId={from} toScanId={to}
              onCountLoaded={(n) => onCount('components', n)} />
          )}
        </TabsContent>
        <TabsContent value="crypto">
          {visited.has('crypto') && (
            <CryptoDeltaTab projectId={id} fromScanId={from} toScanId={to}
              onCountLoaded={(n) => onCount('crypto', n)} />
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
