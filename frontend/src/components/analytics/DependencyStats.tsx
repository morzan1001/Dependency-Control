import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getTopDependencies, getDependencyTypes, DependencyUsage } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { AlertTriangle, Package } from 'lucide-react'

interface DependencyStatsProps {
  onSelectDependency?: (dep: DependencyUsage) => void;
}

export function DependencyStats({ onSelectDependency }: DependencyStatsProps) {
  const [selectedType, setSelectedType] = useState<string | undefined>(undefined)
  const [limit, setLimit] = useState(20)

  const { data: types } = useQuery({
    queryKey: ['dependency-types'],
    queryFn: getDependencyTypes,
  })

  const { data: dependencies, isLoading } = useQuery({
    queryKey: ['top-dependencies', limit, selectedType],
    queryFn: () => getTopDependencies(limit, selectedType),
  })

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Top Dependencies</CardTitle>
            <CardDescription>Most frequently used packages across your projects</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Select value={selectedType || "all"} onValueChange={(v) => setSelectedType(v === "all" ? undefined : v)}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="All types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All types</SelectItem>
                {types?.map((t) => (
                  <SelectItem key={t} value={t}>{t}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={limit.toString()} onValueChange={(v) => setLimit(parseInt(v))}>
              <SelectTrigger className="w-[100px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="10">Top 10</SelectItem>
                <SelectItem value="20">Top 20</SelectItem>
                <SelectItem value="50">Top 50</SelectItem>
                <SelectItem value="100">Top 100</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array(5).fill(0).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : dependencies && dependencies.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Package</TableHead>
                <TableHead>Type</TableHead>
                <TableHead className="text-center">Projects</TableHead>
                <TableHead className="text-center">Occurrences</TableHead>
                <TableHead>Versions</TableHead>
                <TableHead className="text-center">Vulnerabilities</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {dependencies.map((dep) => (
                <TableRow 
                  key={dep.name} 
                  className={onSelectDependency ? "cursor-pointer hover:bg-muted" : ""}
                  onClick={() => onSelectDependency?.(dep)}
                >
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Package className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{dep.name}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary">{dep.type}</Badge>
                  </TableCell>
                  <TableCell className="text-center">{dep.project_count}</TableCell>
                  <TableCell className="text-center">{dep.total_occurrences}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {dep.versions.slice(0, 3).map((v) => (
                        <Badge key={v} variant="outline" className="text-xs">{v}</Badge>
                      ))}
                      {dep.versions.length > 3 && (
                        <Badge variant="outline" className="text-xs">+{dep.versions.length - 3}</Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-center">
                    {dep.has_vulnerabilities ? (
                      <div className="flex items-center justify-center gap-1 text-destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <span>{dep.vulnerability_count}</span>
                      </div>
                    ) : (
                      <span className="text-muted-foreground">-</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
            <Package className="h-12 w-12 mb-4" />
            <p>No dependencies found</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
