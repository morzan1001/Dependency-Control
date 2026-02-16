import { useState, useEffect } from 'react'
import { useInfiniteQuery, keepPreviousData } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { analyticsApi } from '@/api/analytics'
import { AdvancedSearchResult } from '@/types/analytics'
import { useDependencyTypes } from '@/hooks/queries/use-analytics'
import { useProjectsDropdown } from '@/hooks/queries/use-projects'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Search, Package, Filter, X, Container, FileCode, HardDrive, Loader2 } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useDebounce } from '@/hooks/use-debounce'
import { DEFAULT_PAGE_SIZE, VIRTUAL_SCROLL_OVERSCAN } from '@/lib/constants'
import { useScrollContainer, createScrollObserver } from '@/hooks/use-scroll-container'

interface CrossProjectSearchProps {
  onSelectResult?: (result: AdvancedSearchResult) => void;
}

export function CrossProjectSearch({ onSelectResult }: CrossProjectSearchProps) {
  const [query, setQuery] = useState('')
  const [version, setVersion] = useState('')
  const [selectedType, setSelectedType] = useState<string>('__all__')
  const [selectedSourceType, setSelectedSourceType] = useState<string>('__all__')
  const [hasVulnerabilities, setHasVulnerabilities] = useState<string>('__all__')
  const [selectedProject, setSelectedProject] = useState<string>('__all__')
  const [showFilters, setShowFilters] = useState(false)

  const { parentRef, scrollContainer, tableOffset } = useScrollContainer()
  const debouncedQuery = useDebounce(query, 300)

  const { data: types } = useDependencyTypes()
  const { data: projectsData } = useProjectsDropdown()

  const {
    data,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    isLoading
  } = useInfiniteQuery({
    queryKey: ['advanced-search', debouncedQuery, version, selectedType, selectedSourceType, hasVulnerabilities, selectedProject],
    queryFn: async ({ pageParam = 0 }) => {
      return analyticsApi.searchDependenciesAdvanced(debouncedQuery, {
        version: version || undefined,
        type: selectedType !== '__all__' ? selectedType : undefined,
        source_type: selectedSourceType !== '__all__' ? selectedSourceType : undefined,
        has_vulnerabilities: hasVulnerabilities === '__all__' ? undefined : hasVulnerabilities === 'true',
        project_ids: selectedProject !== '__all__' ? [selectedProject] : undefined,
        skip: pageParam,
        limit: DEFAULT_PAGE_SIZE,
      })
    },
    initialPageParam: 0,
    getNextPageParam: (lastPage) => {
      const nextSkip = lastPage.page * lastPage.size
      return nextSkip < lastPage.total ? nextSkip : undefined
    },
    placeholderData: keepPreviousData,
    enabled: debouncedQuery.length >= 2,
  })

  const allResults = data ? data.pages.flatMap((d) => d.items) : []
  const totalCount = data?.pages[0]?.total ?? 0

  // eslint-disable-next-line react-hooks/incompatible-library
  const rowVirtualizer = useVirtualizer({
    count: hasNextPage ? allResults.length + 1 : allResults.length,
    getScrollElement: () => scrollContainer,
    estimateSize: () => 52,
    overscan: VIRTUAL_SCROLL_OVERSCAN,
    observeElementOffset: createScrollObserver(scrollContainer, tableOffset),
  })

  const virtualItems = rowVirtualizer.getVirtualItems()
  const lastItemIndex = virtualItems.length > 0 ? virtualItems[virtualItems.length - 1]?.index : -1

  useEffect(() => {
    if (lastItemIndex === -1) return
    if (lastItemIndex >= allResults.length - 1 && hasNextPage && !isFetchingNextPage) {
      fetchNextPage()
    }
  }, [hasNextPage, fetchNextPage, allResults.length, isFetchingNextPage, lastItemIndex])

  const projects = projectsData?.items || []

  const clearFilters = () => {
    setVersion('')
    setSelectedType('__all__')
    setSelectedSourceType('__all__')
    setHasVulnerabilities('__all__')
    setSelectedProject('__all__')
  }

  const hasActiveFilters = version || selectedType !== '__all__' || selectedSourceType !== '__all__' || hasVulnerabilities !== '__all__' || selectedProject !== '__all__'

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
        {/* Search Input */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search for a package name (e.g., react, lodash, requests)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-10"
          />
        </div>

        {/* Filters Panel */}
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
              {/* Version Filter */}
              <div className="space-y-2">
                <Label>Version</Label>
                <Input
                  placeholder="e.g., 1.0.0"
                  value={version}
                  onChange={(e) => setVersion(e.target.value)}
                />
              </div>

              {/* Type Filter */}
              <div className="space-y-2">
                <Label>Package Type</Label>
                <Select value={selectedType} onValueChange={setSelectedType}>
                  <SelectTrigger>
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

              {/* Source Type Filter */}
              <div className="space-y-2">
                <Label>Source</Label>
                <Select value={selectedSourceType} onValueChange={setSelectedSourceType}>
                  <SelectTrigger>
                    <SelectValue placeholder="All sources" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">All sources</SelectItem>
                    <SelectItem value="image">
                      <div className="flex items-center gap-2">
                        <Container className="h-4 w-4 text-blue-500" />
                        Docker Image
                      </div>
                    </SelectItem>
                    <SelectItem value="file">
                      <div className="flex items-center gap-2">
                        <FileCode className="h-4 w-4 text-green-500" />
                        Source File
                      </div>
                    </SelectItem>
                    <SelectItem value="directory">
                      <div className="flex items-center gap-2">
                        <HardDrive className="h-4 w-4 text-amber-500" />
                        Directory
                      </div>
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Vulnerability Filter */}
              <div className="space-y-2">
                <Label>Vulnerability Status</Label>
                <Select 
                  value={hasVulnerabilities} 
                  onValueChange={setHasVulnerabilities}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="All" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">All packages</SelectItem>
                    <SelectItem value="true">With vulnerabilities</SelectItem>
                    <SelectItem value="false">Without vulnerabilities</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Project Filter */}
              <div className="space-y-2">
                <Label>Projects</Label>
                <Select 
                  value={selectedProject}
                  onValueChange={setSelectedProject}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="All projects" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">All projects</SelectItem>
                    {projects.map((p) => (
                      <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        <div ref={parentRef}>
          {query.length < 2 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Search className="h-12 w-12 mb-4" />
              <p>Enter at least 2 characters to search</p>
            </div>
          ) : isLoading ? (
            <div className="space-y-2">
              {new Array(5).fill(0).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : allResults.length > 0 ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">
                  Showing {allResults.length} of {totalCount} result{totalCount !== 1 ? 's' : ''}
                </p>
                {isFetchingNextPage && (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading more...
                  </div>
                )}
              </div>
              <div className="border rounded-lg overflow-hidden">
                <Table className="table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[250px]">Package</TableHead>
                    <TableHead className="w-[120px]">Version</TableHead>
                    <TableHead className="w-[100px]">Type</TableHead>
                    <TableHead className="w-[150px]">License</TableHead>
                    <TableHead className="w-[200px]">Project</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <tr>
                    <td colSpan={5} className="p-0">
                      <div
                        style={{
                          height: `${rowVirtualizer.getTotalSize()}px`,
                          position: 'relative',
                        }}
                      >
                        {virtualItems.map((virtualRow) => {
                          const isLoaderRow = virtualRow.index >= allResults.length
                          if (isLoaderRow) {
                            return (
                              <div
                                key="loader"
                                className="absolute left-0 right-0 flex items-center justify-center py-4"
                                style={{
                                  top: `${virtualRow.start}px`,
                                  height: `${virtualRow.size}px`,
                                }}
                              >
                                <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                              </div>
                            )
                          }
                          const result = allResults[virtualRow.index]
                          return (
                            <div
                              key={`${result.project_id}-${result.package}-${result.version}-${virtualRow.index}`}
                              className="flex items-center border-b cursor-pointer hover:bg-muted transition-colors"
                              style={{
                                position: 'absolute',
                                top: `${virtualRow.start}px`,
                                left: 0,
                                right: 0,
                                height: `${virtualRow.size}px`,
                              }}
                              onClick={() => onSelectResult?.(result)}
                            >
                              <div className="w-[250px] px-4 py-2 truncate">
                                <div className="flex items-center gap-2 min-w-0">
                                  <Package className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                                  <span className="font-medium truncate">{result.package}</span>
                                </div>
                              </div>
                              <div className="w-[120px] px-4 py-2 truncate">
                                <Badge variant="outline" className="truncate max-w-full">{result.version}</Badge>
                              </div>
                              <div className="w-[100px] px-4 py-2">
                                <Badge variant="secondary" className="truncate">{result.type}</Badge>
                              </div>
                              <div className="w-[150px] px-4 py-2 truncate">
                                <span className="truncate block">{result.license || <span className="text-muted-foreground">-</span>}</span>
                              </div>
                              <div className="w-[200px] px-4 py-2 truncate">
                                <Link
                                  to={`/projects/${result.project_id}`}
                                  className="hover:underline text-primary truncate block"
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  {result.project_name}
                                </Link>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    </td>
                  </tr>
                </TableBody>
              </Table>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Package className="h-12 w-12 mb-4" />
            <p>No packages found matching "{query}"</p>
            {hasActiveFilters && (
              <Button variant="link" onClick={clearFilters}>
                Try clearing filters
              </Button>
            )}
          </div>
        )}
        </div>
      </CardContent>
    </Card>
  )
}
