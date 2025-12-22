import { useState, useRef, useEffect, useLayoutEffect } from 'react'
import { useInfiniteQuery, useQuery, keepPreviousData } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { getDependenciesList, getDependencyTypes, DependencyListItem } from '@/lib/api'
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
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { Package, AlertTriangle, ArrowUp, ArrowDown, Loader2, Container, FileCode, HardDrive } from 'lucide-react'
import { Link } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { AnalyticsDependencyModal } from './AnalyticsDependencyModal'
import { DEFAULT_PAGE_SIZE, VIRTUAL_SCROLL_OVERSCAN } from '@/lib/constants'

// Helper to get source icon and label
function getSourceInfo(sourceType?: string) {
  switch (sourceType) {
    case 'image':
      return { icon: Container, label: 'Docker Image', color: 'text-blue-500', bgColor: 'bg-blue-500/10' }
    case 'file':
      return { icon: FileCode, label: 'Source File', color: 'text-green-500', bgColor: 'bg-green-500/10' }
    case 'directory':
      return { icon: HardDrive, label: 'Directory', color: 'text-amber-500', bgColor: 'bg-amber-500/10' }
    default:
      return null
  }
}

type SortField = 'name' | 'version' | 'type' | 'project_name' | 'direct'
type SortOrder = 'asc' | 'desc'

// Selected dependency for the modal
interface SelectedDep {
  name: string;
  version: string;
  type: string;
}

export function DependencyList() {
  const [selectedType, setSelectedType] = useState<string>('__all__')
  const [sortBy, setSortBy] = useState<SortField>('name')
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc')
  const [selectedDep, setSelectedDep] = useState<SelectedDep | null>(null)
  const [modalOpen, setModalOpen] = useState(false)

  const parentRef = useRef<HTMLDivElement>(null)
  const [scrollContainer, setScrollContainer] = useState<HTMLElement | null>(null)
  const [tableOffset, setTableOffset] = useState(0)

  useLayoutEffect(() => {
    const container = document.querySelector('main') as HTMLElement
    setScrollContainer(container)

    if (container && parentRef.current) {
      const updateOffset = () => {
        if (parentRef.current && container) {
          const rect = parentRef.current.getBoundingClientRect()
          const containerRect = container.getBoundingClientRect()
          setTableOffset(rect.top - containerRect.top + container.scrollTop)
        }
      }
      updateOffset()
      window.addEventListener('resize', updateOffset)
      return () => window.removeEventListener('resize', updateOffset)
    }
  }, [])

  const { data: types } = useQuery({
    queryKey: ['dependency-types'],
    queryFn: getDependencyTypes,
  })

  const {
    data,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    isLoading
  } = useInfiniteQuery({
    queryKey: ['dependencies-list', selectedType, sortBy, sortOrder],
    queryFn: async ({ pageParam = 1 }) => {
      return getDependenciesList({
        page: pageParam,
        size: DEFAULT_PAGE_SIZE,
        sort_by: sortBy,
        sort_order: sortOrder,
        type_filter: selectedType !== '__all__' ? selectedType : undefined,
      })
    },
    initialPageParam: 1,
    getNextPageParam: (lastPage) => {
      return lastPage.has_more ? lastPage.page + 1 : undefined
    },
    placeholderData: keepPreviousData,
  })

  const allResults = data?.pages.flatMap((page) => page.items) ?? []
  const totalCount = data?.pages[0]?.total ?? 0

  const virtualizer = useVirtualizer({
    count: hasNextPage ? allResults.length + 1 : allResults.length,
    getScrollElement: () => scrollContainer,
    estimateSize: () => 48,
    overscan: VIRTUAL_SCROLL_OVERSCAN,
    scrollMargin: tableOffset,
  })

  const virtualItems = virtualizer.getVirtualItems()

  useEffect(() => {
    const lastItem = virtualItems[virtualItems.length - 1]
    if (
      lastItem &&
      lastItem.index >= allResults.length - 1 &&
      hasNextPage &&
      !isFetchingNextPage
    ) {
      fetchNextPage()
    }
  }, [virtualItems, allResults.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  const handleSort = (field: SortField) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(field)
      setSortOrder('desc')
    }
  }

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortBy !== field) return null
    return sortOrder === 'asc' 
      ? <ArrowUp className="h-4 w-4 inline-block ml-1" />
      : <ArrowDown className="h-4 w-4 inline-block ml-1" />
  }

  const handleRowClick = (dep: DependencyListItem) => {
    setSelectedDep({
      name: dep.name,
      version: dep.version,
      type: dep.type || 'unknown',
    })
    setModalOpen(true)
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>All Dependencies</CardTitle>
            <CardDescription>
              {totalCount > 0 
                ? `${totalCount.toLocaleString()} dependencies across all projects`
                : 'Loading dependencies...'}
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Select value={selectedType} onValueChange={setSelectedType}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="All types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__all__">All types</SelectItem>
                {types?.map((t) => (
                  <SelectItem key={t} value={t}>{t}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array(10).fill(0).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : allResults.length > 0 ? (
          <div ref={parentRef}>
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead 
                    className="w-[200px] cursor-pointer hover:bg-muted/50"
                    onClick={() => handleSort('name')}
                  >
                    Package
                    <SortIcon field="name" />
                  </TableHead>
                  <TableHead 
                    className="w-[100px] cursor-pointer hover:bg-muted/50"
                    onClick={() => handleSort('version')}
                  >
                    Version
                    <SortIcon field="version" />
                  </TableHead>
                  <TableHead 
                    className="w-[80px] cursor-pointer hover:bg-muted/50"
                    onClick={() => handleSort('type')}
                  >
                    Type
                    <SortIcon field="type" />
                  </TableHead>
                  <TableHead className="w-[130px]">Source</TableHead>
                  <TableHead className="w-[120px]">License</TableHead>
                  <TableHead 
                    className="w-[150px] cursor-pointer hover:bg-muted/50"
                    onClick={() => handleSort('project_name')}
                  >
                    Project
                    <SortIcon field="project_name" />
                  </TableHead>
                  <TableHead 
                    className="w-[100px] cursor-pointer hover:bg-muted/50"
                    onClick={() => handleSort('direct')}
                  >
                    Dep Type
                    <SortIcon field="direct" />
                  </TableHead>
                  <TableHead className="w-[100px] text-center">Vulns</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {virtualItems.map((virtualRow) => {
                  const isLoaderRow = virtualRow.index >= allResults.length
                  if (isLoaderRow) {
                    return (
                      <TableRow key="loader">
                        <TableCell colSpan={8} className="text-center py-4">
                          <div className="flex items-center justify-center gap-2 text-muted-foreground">
                            <Loader2 className="h-4 w-4 animate-spin" />
                            Loading more dependencies...
                          </div>
                        </TableCell>
                      </TableRow>
                    )
                  }
                  const dep = allResults[virtualRow.index]
                  const sourceInfo = getSourceInfo(dep.source_type)
                  return (
                    <TableRow 
                      key={`${dep.project_id}-${dep.name}-${dep.version}-${virtualRow.index}`}
                      className="cursor-pointer hover:bg-muted"
                      onClick={() => handleRowClick(dep)}
                    >
                      <TableCell className="truncate">
                        <div className="flex items-center gap-2 min-w-0">
                          <Package className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                          <span className="font-medium truncate">{dep.name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="truncate">
                        <Badge variant="outline" className="whitespace-nowrap">{dep.version}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="whitespace-nowrap">{dep.type}</Badge>
                      </TableCell>
                      <TableCell>
                        {sourceInfo ? (
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <div className={cn("flex items-center gap-1 px-1.5 py-0.5 rounded-md w-fit text-xs", sourceInfo.bgColor)}>
                                  <sourceInfo.icon className={cn("h-3.5 w-3.5 flex-shrink-0", sourceInfo.color)} />
                                  <span className="font-medium truncate">{sourceInfo.label}</span>
                                </div>
                              </TooltipTrigger>
                              <TooltipContent>
                                <p>{sourceInfo.label}</p>
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        ) : (
                          <span className="text-muted-foreground text-sm">-</span>
                        )}
                      </TableCell>
                      <TableCell className="truncate">
                        <span className="text-sm truncate">{dep.license || '-'}</span>
                      </TableCell>
                      <TableCell className="truncate">
                        <Link 
                          to={`/projects/${dep.project_id}`}
                          className="text-primary hover:underline truncate block"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {dep.project_name}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <Badge 
                          variant={dep.direct ? "default" : "secondary"}
                          className={cn(
                            dep.direct 
                              ? "bg-green-500/20 text-green-700 dark:text-green-300 hover:bg-green-500/30" 
                              : "bg-gray-500/20 text-gray-700 dark:text-gray-300"
                          )}
                        >
                          {dep.direct ? 'Direct' : 'Transitive'}
                        </Badge>
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
                  )
                })}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
            <Package className="h-12 w-12 mb-4" />
            <p>No dependencies found</p>
          </div>
        )}

        {/* Analytics Dependency Modal */}
        {selectedDep && (
          <AnalyticsDependencyModal
            component={selectedDep.name}
            version={selectedDep.version}
            type={selectedDep.type}
            open={modalOpen}
            onOpenChange={setModalOpen}
          />
        )}
      </CardContent>
    </Card>
  )
}
