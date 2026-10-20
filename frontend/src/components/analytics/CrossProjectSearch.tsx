import { useState } from 'react'
import { useInfiniteQuery } from '@tanstack/react-query'
import { analyticsApi } from '@/api/analytics'
import { AdvancedSearchResult } from '@/types/analytics'
import { analyticsKeys, useDependencyTypes } from '@/hooks/queries/use-analytics'
import { useAnalyticsMode } from '@/context/analytics-mode'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { VirtualRows } from '@/components/ui/virtual-rows'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { ProjectCombobox } from '@/components/ui/project-combobox'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Search, Package, Filter, X } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useDebounce } from '@/hooks/use-debounce'
import { useInfiniteRows } from '@/hooks/use-infinite-rows'
import { DEFAULT_PAGE_SIZE } from '@/lib/constants'
import { useScrollContainer } from '@/hooks/use-scroll-container'
import { getSourceInfo } from '@/lib/finding-utils'
import { sharedNames } from '@/lib/utils'
import { ProjectOwnerById } from '@/components/project/ProjectOwner'
import { AnalyticsErrorCard } from './AnalyticsErrorCard'

interface CrossProjectSearchProps {
  onSelectResult?: (result: AdvancedSearchResult) => void;
}

const CROSS_PROJECT_SKELETON_IDS = ['cps1', 'cps2', 'cps3', 'cps4', 'cps5']

export function CrossProjectSearch({ onSelectResult }: Readonly<CrossProjectSearchProps>) {
  const [query, setQuery] = useState('')
  const [version, setVersion] = useState('')
  const [selectedType, setSelectedType] = useState<string>('__all__')
  const [selectedSourceType, setSelectedSourceType] = useState<string>('__all__')
  const [hasVulnerabilities, setHasVulnerabilities] = useState<string>('__all__')
  const [selectedProject, setSelectedProject] = useState('')
  const [showFilters, setShowFilters] = useState(false)

  const { parentRef, scrollContainer, tableOffsetRef } = useScrollContainer()
  const debouncedQuery = useDebounce(query, 300)
  const debouncedVersion = useDebounce(version, 300)

  const releaseEnvironment = useAnalyticsMode()
  const { data: types } = useDependencyTypes(releaseEnvironment)

  const filters = {
    query: debouncedQuery,
    version: debouncedVersion,
    type: selectedType,
    sourceType: selectedSourceType,
    hasVulnerabilities,
    project: selectedProject,
  }

  const results = useInfiniteQuery({
    queryKey: analyticsKeys.advancedSearch(filters, releaseEnvironment),
    queryFn: async ({ pageParam = 0 }) => {
      return analyticsApi.searchDependenciesAdvanced(debouncedQuery, {
        version: debouncedVersion || undefined,
        type: selectedType === '__all__' ? undefined : selectedType,
        source_type: selectedSourceType === '__all__' ? undefined : selectedSourceType,
        has_vulnerabilities: hasVulnerabilities === '__all__' ? undefined : hasVulnerabilities === 'true',
        project_ids: selectedProject ? [selectedProject] : undefined,
        skip: pageParam,
        limit: DEFAULT_PAGE_SIZE,
        release_environment: releaseEnvironment,
      })
    },
    initialPageParam: 0,
    getNextPageParam: (lastPage, allPages) => {
      const totalLoaded = allPages.reduce((sum, page) => sum + page.items.length, 0)
      return totalLoaded < lastPage.total ? totalLoaded : undefined
    },
    enabled: debouncedQuery.length >= 2,
  })

  const { isLoading, error } = results
  const list = useInfiniteRows(results, (page) => page.items)
  const allResults = list.rows
  const namesakes = sharedNames(allResults.map((result) => ({ id: result.project_id, name: result.project_name })))
  const totalCount = results.data?.pages[0]?.total ?? 0

  const clearFilters = () => {
    setVersion('')
    setSelectedType('__all__')
    setSelectedSourceType('__all__')
    setHasVulnerabilities('__all__')
    setSelectedProject('')
  }

  const hasActiveFilters = version || selectedType !== '__all__' || selectedSourceType !== '__all__' || hasVulnerabilities !== '__all__' || selectedProject !== ''

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Cross-Project Search</CardTitle>
            <CardDescription>
              Search for dependencies across all your projects with advanced filters
            </CardDescription>
          </div>
          <Button
            variant={showFilters ? "default" : "outline"}
            size="sm"
            type="button"
            aria-expanded={showFilters}
            onClick={() => setShowFilters(!showFilters)}
          >
            <Filter className="h-4 w-4 mr-2" />
            Filters
            {hasActiveFilters && (
              <Badge variant="secondary" className="ml-2">Active</Badge>
            )}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            aria-label="Search packages"
            placeholder="Search for a package name (e.g., react, lodash, requests)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-10"
          />
        </div>

        {showFilters && (
          <div className="p-4 border rounded-lg bg-muted/50 space-y-4">
            <div className="flex items-center justify-between">
              <h4 className="font-medium">Filters</h4>
              {hasActiveFilters && (
                <Button variant="ghost" size="sm" type="button" onClick={clearFilters}>
                  <X className="h-4 w-4 mr-1" />
                  Clear all
                </Button>
              )}
            </div>
            
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
              <div className="space-y-2">
                <Label htmlFor="dependency-search-version">Version</Label>
                <Input
                  id="dependency-search-version"
                  placeholder="e.g., 1.0.0"
                  value={version}
                  onChange={(e) => setVersion(e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="dependency-search-type">Package Type</Label>
                <Select value={selectedType} onValueChange={setSelectedType}>
                  <SelectTrigger id="dependency-search-type">
                    <SelectValue placeholder="All types" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">All types</SelectItem>
                    {types?.map((t: string) => (
                      <SelectItem key={t} value={t}>{t}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="dependency-search-source">Source</Label>
                <Select value={selectedSourceType} onValueChange={setSelectedSourceType}>
                  <SelectTrigger id="dependency-search-source">
                    <SelectValue placeholder="All sources" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">All sources</SelectItem>
                    {['image', 'file', 'directory'].map((sourceType) => {
                      const { icon: Icon, label, color } = getSourceInfo(sourceType)!
                      return (
                        <SelectItem key={sourceType} value={sourceType}>
                          <div className="flex items-center gap-2">
                            <Icon className={`h-4 w-4 ${color}`} />
                            {label}
                          </div>
                        </SelectItem>
                      )
                    })}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="dependency-search-vulnerable">Vulnerability Status</Label>
                <Select 
                  value={hasVulnerabilities} 
                  onValueChange={setHasVulnerabilities}
                >
                  <SelectTrigger id="dependency-search-vulnerable">
                    <SelectValue placeholder="All" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">All packages</SelectItem>
                    <SelectItem value="true">With vulnerabilities</SelectItem>
                    <SelectItem value="false">Without vulnerabilities</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="dependency-search-project">Project</Label>
                <ProjectCombobox id="dependency-search-project" value={selectedProject} onValueChange={setSelectedProject} />
              </div>
            </div>
          </div>
        )}

        <div ref={parentRef}>
          {(() => {
            if (query.length < 2) {
              return (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Search className="h-12 w-12 mb-4" />
                  <p>Enter at least 2 characters to search</p>
                </div>
              )
            }
            if (isLoading) {
              return (
                <div className="space-y-2">
                  {CROSS_PROJECT_SKELETON_IDS.map((id) => (
                    <Skeleton key={id} className="h-12 w-full" />
                  ))}
                </div>
              )
            }
            if (error && allResults.length === 0) {
              return <AnalyticsErrorCard title="Failed to search dependencies" error={error} onRetry={list.retry} />
            }
            if (allResults.length > 0) {
              return (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">
                  Showing {allResults.length} of {totalCount} result{totalCount !== 1 ? 's' : ''}
                </p>
              </div>
              <div className="border rounded-lg overflow-hidden">
                {/* The rows are flex rows that shrink apart from the header once the table is narrower than their columns. */}
                <Table className="table-fixed min-w-[820px]">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[250px]">Package</TableHead>
                    <TableHead className="w-[120px]">Version</TableHead>
                    <TableHead className="w-[100px]">Type</TableHead>
                    <TableHead className="w-[150px]">License</TableHead>
                    <TableHead>Project</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <VirtualRows
                    list={list}
                    scrollContainer={scrollContainer}
                    tableOffsetRef={tableOffsetRef}
                    estimateSize={52}
                    rowKey={(result) => `${result.project_id}-${result.package}-${result.version}`}
                    colSpan={5}
                    renderRow={(result, style) => (
                      <div
                        className="flex items-center border-b cursor-pointer hover:bg-muted transition-colors"
                        role="row"
                        tabIndex={0}
                        style={style}
                        onClick={() => onSelectResult?.(result)}
                        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelectResult?.(result); } }}
                      >
                        <div role="cell" className="w-[250px] px-4 py-2 truncate">
                          <div className="flex items-center gap-2 min-w-0">
                            <Package className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            <span className="font-medium truncate">{result.package}</span>
                          </div>
                        </div>
                        <div role="cell" className="w-[120px] px-4 py-2 truncate">
                          <Badge variant="outline" className="truncate max-w-full">{result.version}</Badge>
                        </div>
                        <div role="cell" className="w-[100px] px-4 py-2">
                          <Badge variant="secondary" className="truncate">{result.type}</Badge>
                        </div>
                        <div role="cell" className="w-[150px] px-4 py-2 truncate">
                          <span className="truncate block">{result.license || <span className="text-muted-foreground">-</span>}</span>
                        </div>
                        <div role="cell" className="flex flex-1 min-w-0 items-center gap-2 px-4 py-2">
                          <Link
                            to={`/projects/${result.project_id}`}
                            className="hover:underline text-primary truncate block"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {result.project_name}
                          </Link>
                          {namesakes.has(result.project_name) && (
                            <ProjectOwnerById projectId={result.project_id} namesakeIds={namesakes.get(result.project_name)} />
                          )}
                        </div>
                      </div>
                    )}
                  />
                </TableBody>
              </Table>
            </div>
            {list.nextPageFailed && (
              <AnalyticsErrorCard title="Failed to load more dependencies" error={error} onRetry={list.retry} />
            )}
          </div>
              )
            }
            return (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Package className="h-12 w-12 mb-4" />
                <p>No packages found matching "{query}"</p>
                {hasActiveFilters && (
                  <Button variant="link" onClick={clearFilters}>
                    Try clearing filters
                  </Button>
                )}
              </div>
            )
          })()}
        </div>
      </CardContent>
    </Card>
  )
}
