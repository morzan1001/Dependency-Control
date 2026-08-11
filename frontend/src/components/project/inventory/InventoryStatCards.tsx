import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Boxes, KeyRound, Package, Scale } from 'lucide-react'
import { InventoryStats } from '@/types/inventory'

interface InventoryStatCardsProps {
  stats?: InventoryStats
  isLoading: boolean
}

export function InventoryStatCards({ stats, isLoading }: InventoryStatCardsProps) {
  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {['i1', 'i2', 'i3', 'i4'].map((id) => <Skeleton key={id} className="h-32 rounded-xl" />)}
      </div>
    )
  }
  if (!stats) return null

  const tiles = [
    {
      title: 'Components',
      value: stats.components_total.toLocaleString(),
      icon: Package,
      description: `${stats.direct_count} direct · ${stats.transitive_count} transitive`,
    },
    { title: 'Licenses', value: stats.license_count.toLocaleString(), icon: Scale, description: 'Distinct licenses in use' },
    { title: 'Ecosystems', value: stats.ecosystem_count.toLocaleString(), icon: Boxes, description: 'npm, pypi, maven, …' },
    { title: 'Crypto Assets', value: stats.crypto_asset_count.toLocaleString(), icon: KeyRound, description: 'Algorithms, certificates, protocols' },
  ]

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {tiles.map((tile) => (
        <Card key={tile.title}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{tile.title}</CardTitle>
            <tile.icon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{tile.value}</div>
            <p className="text-xs text-muted-foreground">{tile.description}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
