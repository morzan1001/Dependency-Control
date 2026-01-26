import { useInfiniteQuery, keepPreviousData } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useEffect, useState } from 'react'
import { scanApi } from '@/api/scans'
import { Finding } from '@/types/scan'
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Skeleton } from '@/components/ui/skeleton'
import { InlineError, NoData } from '@/components/ui/state-components'
import { FindingDetailsModal } from './FindingDetailsModal'
import { ArrowUp, ArrowDown, Shield, AlertTriangle, Loader2 } from 'lucide-react';
import { DEFAULT_PAGE_SIZE, VIRTUAL_SCROLL_OVERSCAN } from '@/lib/constants';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { SeverityBadge } from './SeverityBadge'
import { FindingTypeBadge } from './FindingTypeBadge'
import { getSourceInfo } from '@/lib/finding-utils'
import { ScanContext } from './details/SastDetailsView'
import { useScrollContainer, createScrollObserver } from '@/hooks/use-scroll-container'

interface FindingsTableProps {
    scanId: string;
    projectId: string;
    category?: string;
    search?: string;
    scanContext?: ScanContext;
}

export function FindingsTable({ scanId, projectId, category, search, scanContext }: FindingsTableProps) {
    const { parentRef, scrollContainer, tableOffset } = useScrollContainer()
    const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
    const [sortBy, setSortBy] = useState("severity")
    const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc")

    const {
        data,
        fetchNextPage,
        hasNextPage,
        isFetchingNextPage,
        isLoading,
        isError
    } = useInfiniteQuery({
        queryKey: ['findings', scanId, category, search, sortBy, sortOrder],
        queryFn: async ({ pageParam = 0 }) => {
            const res = await scanApi.getFindings(scanId, {
                skip: pageParam,
                limit: DEFAULT_PAGE_SIZE,
                category,
                search,
                sort_by: sortBy,
                sort_order: sortOrder
            });
            return res;
        },
        initialPageParam: 0,
        getNextPageParam: (lastPage) => {
            const nextSkip = (lastPage.page * lastPage.size);
            return nextSkip < lastPage.total ? nextSkip : undefined;
        },
        placeholderData: keepPreviousData,
    })

    const allRows = data ? data.pages.flatMap((d) => d.items) : []

    // eslint-disable-next-line
    const rowVirtualizer = useVirtualizer({
        count: hasNextPage ? allRows.length + 1 : allRows.length,
        getScrollElement: () => scrollContainer,
        estimateSize: () => 60,
        overscan: VIRTUAL_SCROLL_OVERSCAN,
        observeElementOffset: createScrollObserver(scrollContainer, tableOffset),
    })

    const virtualItems = rowVirtualizer.getVirtualItems()
    const lastItemIndex = virtualItems.length > 0 ? virtualItems[virtualItems.length - 1]?.index : -1

    useEffect(() => {
        if (!scrollContainer) return
        rowVirtualizer.measure()
    }, [scrollContainer, allRows.length, rowVirtualizer])

    useEffect(() => {
        if (!parentRef.current || typeof ResizeObserver === 'undefined') return

        const observer = new ResizeObserver(() => {
            rowVirtualizer.measure()
        })

        observer.observe(parentRef.current)

        if (scrollContainer) {
            observer.observe(scrollContainer)
        }

        return () => observer.disconnect()
    }, [parentRef, scrollContainer, rowVirtualizer])

    useEffect(() => {
        if (lastItemIndex === -1) {
            return
        }

        if (
            lastItemIndex >= allRows.length - 1 &&
            hasNextPage &&
            !isFetchingNextPage
        ) {
            fetchNextPage()
        }
    }, [
        hasNextPage,
        fetchNextPage,
        allRows.length,
        isFetchingNextPage,
        lastItemIndex,
    ])

    const renderSortIcon = (column: string) => {
        if (sortBy === column) {
            return sortOrder === 'asc' ? <ArrowUp className="ml-2 h-4 w-4 inline" /> : <ArrowDown className="ml-2 h-4 w-4 inline" />
        }
        return null;
    };

    const handleSort = (column: string) => {
        if (sortBy === column) {
            setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
        } else {
            setSortBy(column);
            setSortOrder('desc');
        }
    };

    return (
        <div ref={parentRef} className="relative w-full">
            {isLoading ? (
                <div className="relative">
                    <table className="w-full text-sm table-fixed">
                        <TableHeader className="sticky top-0 bg-background z-50 shadow-sm">
                            <TableRow className="w-full">
                                <TableHead className="w-[120px] bg-background">Severity</TableHead>
                                <TableHead className="w-[200px] bg-background">ID</TableHead>
                                <TableHead className="w-auto bg-background">Component</TableHead>
                                <TableHead className="w-[80px] bg-background">Source</TableHead>
                                <TableHead className="w-[120px] bg-background">Type</TableHead>
                                <TableHead className="w-[150px] bg-background">Scanner</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {Array.from({ length: 10 }).map((_, i) => (
                                <TableRow key={i} className="w-full border-b">
                                    <TableCell className="p-4"><Skeleton className="h-6 w-16" /></TableCell>
                                    <TableCell className="p-4"><Skeleton className="h-6 w-24" /></TableCell>
                                    <TableCell className="p-4"><Skeleton className="h-6 w-32" /></TableCell>
                                    <TableCell className="p-4"><Skeleton className="h-6 w-8" /></TableCell>
                                    <TableCell className="p-4"><Skeleton className="h-6 w-20" /></TableCell>
                                    <TableCell className="p-4"><Skeleton className="h-6 w-20" /></TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </table>
                </div>
            ) : isError ? (
                <InlineError message="Error loading findings" />
            ) : allRows.length === 0 ? (
                <NoData entityName="findings" />
            ) : (
                <table className="w-full caption-bottom text-sm table-fixed">
                    <TableHeader className="sticky top-0 bg-background z-50 shadow-sm">
                        <TableRow className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
                            <TableHead className="w-[120px] h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground bg-background" onClick={() => handleSort('severity')}>
                                Severity {renderSortIcon('severity')}
                            </TableHead>
                            <TableHead className="w-[200px] h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground bg-background" onClick={() => handleSort('vuln_id')}>
                                ID {renderSortIcon('vuln_id')}
                            </TableHead>
                            <TableHead className="w-auto h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground bg-background" onClick={() => handleSort('component')}>
                                Component {renderSortIcon('component')}
                            </TableHead>
                            <TableHead className="w-[80px] h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground bg-background" onClick={() => handleSort('source_type')}>
                                Source {renderSortIcon('source_type')}
                            </TableHead>
                            <TableHead className="w-[120px] h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground bg-background" onClick={() => handleSort('type')}>
                                Type {renderSortIcon('type')}
                            </TableHead>
                            <TableHead className="w-[150px] h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground bg-background" onClick={() => handleSort('scanner')}>
                                Scanner {renderSortIcon('scanner')}
                            </TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {rowVirtualizer.getVirtualItems().length > 0 && (
                            <tr style={{ height: `${rowVirtualizer.getVirtualItems()[0].start}px` }}>
                                <td colSpan={6} />
                            </tr>
                        )}
                        {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                            const isLoaderRow = virtualRow.index > allRows.length - 1
                            const finding = allRows[virtualRow.index]
                            const sourceInfo = !isLoaderRow ? getSourceInfo(finding?.source_type) : null

                            return (
                                <TableRow
                                    onClick={() => !isLoaderRow && setSelectedFinding(finding)}
                                    key={isLoaderRow ? `loader-${virtualRow.index}` : finding?.id || `row-${virtualRow.index}`}
                                    data-index={virtualRow.index}
                                    ref={rowVirtualizer.measureElement}
                                    className={`border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted cursor-pointer ${
                                        finding?.type === 'system_warning' ? 'bg-destructive/5 hover:bg-destructive/10 border-l-2 border-l-destructive' : ''
                                    }`}
                                >
                                    {isLoaderRow ? (
                                        <TableCell colSpan={6} className="p-4 text-center">
                                            <Loader2 className="h-6 w-6 animate-spin mx-auto text-muted-foreground" />
                                            <span className="sr-only">Loading more...</span>
                                        </TableCell>
                                    ) : (
                                        <>
                                            <TableCell className="p-4 align-middle">
                                                <div className="flex items-center gap-1.5">
                                                    <SeverityBadge severity={finding.severity} />
                                                    {/* Reachability indicator */}
                                                    {finding.details?.reachability && (
                                                        <TooltipProvider>
                                                            <Tooltip>
                                                                <TooltipTrigger asChild>
                                                                    <div className={`flex items-center justify-center w-5 h-5 rounded-full ${
                                                                        finding.details.reachability.is_reachable
                                                                            ? 'bg-red-100 text-severity-critical'
                                                                            : 'bg-green-100 text-success'
                                                                    }`}>
                                                                        {finding.details.reachability.is_reachable ? (
                                                                            <AlertTriangle className="h-3 w-3" />
                                                                        ) : (
                                                                            <Shield className="h-3 w-3" />
                                                                        )}
                                                                    </div>
                                                                </TooltipTrigger>
                                                                <TooltipContent side="right">
                                                                    <div className="space-y-1">
                                                                        <p className="font-medium">
                                                                            {finding.details.reachability.is_reachable 
                                                                                ? 'Reachable Code' 
                                                                                : 'Not Reachable'}
                                                                        </p>
                                                                        {finding.details.reachability.analysis_level && (
                                                                            <p className="text-xs">
                                                                                Analysis: {finding.details.reachability.analysis_level}
                                                                            </p>
                                                                        )}
                                                                        {finding.details.reachability.confidence_score && (
                                                                            <p className="text-xs">
                                                                                Confidence: {Math.round(finding.details.reachability.confidence_score * 100)}%
                                                                            </p>
                                                                        )}
                                                                    </div>
                                                                </TooltipContent>
                                                            </Tooltip>
                                                        </TooltipProvider>
                                                    )}
                                                </div>
                                            </TableCell>
                                            <TableCell className="p-4 align-middle font-mono text-xs truncate" title={finding.id}>
                                                {finding.type === 'vulnerability' && (finding.details?.vulnerabilities?.length ?? 0) > 1 
                                                    ? 'Multiple Vulnerabilities' 
                                                    : (finding.type === 'vulnerability' && (finding.details?.vulnerabilities?.length ?? 0) === 1 
                                                        ? finding.details?.vulnerabilities?.[0]?.id 
                                                        : finding.type === 'quality' && (finding.details?.quality_issues?.length ?? 0) > 1
                                                            ? 'Multiple Quality Issues'
                                                            : finding.type === 'quality' && (finding.details?.quality_issues?.length ?? 0) === 1
                                                                ? finding.details?.quality_issues?.[0]?.id
                                                                : finding.id)}
                                            </TableCell>
                                            <TableCell className="p-4 align-middle">
                                                <div className="flex flex-col truncate">
                                                    <span className="font-medium truncate" title={finding.component}>{finding.component}</span>
                                                    <span className="text-xs text-muted-foreground truncate" title={finding.version}>{finding.version}</span>
                                                </div>
                                            </TableCell>
                                            <TableCell className="p-4 align-middle">
                                                {sourceInfo ? (
                                                    <TooltipProvider>
                                                        <Tooltip>
                                                            <TooltipTrigger asChild>
                                                                <div className="flex items-center justify-center">
                                                                    <sourceInfo.icon className={`h-5 w-5 ${sourceInfo.color}`} />
                                                                </div>
                                                            </TooltipTrigger>
                                                            <TooltipContent side="top" className="max-w-xs">
                                                                <div className="space-y-1">
                                                                    <p className="font-medium">{sourceInfo.label}</p>
                                                                    {finding.source_target && (
                                                                        <p className="text-xs text-muted-foreground break-all">{finding.source_target}</p>
                                                                    )}
                                                                    {finding.direct !== undefined && (
                                                                        <p className="text-xs">
                                                                            {finding.direct ? "Direct dependency" : "Transitive dependency"}
                                                                        </p>
                                                                    )}
                                                                </div>
                                                            </TooltipContent>
                                                        </Tooltip>
                                                    </TooltipProvider>
                                                ) : (
                                                    <span className="text-muted-foreground text-center block">-</span>
                                                )}
                                            </TableCell>
                                            <TableCell className="p-4 align-middle">
                                                <div className="flex flex-wrap gap-1">
                                                    <FindingTypeBadge type={finding.type} />
                                                    {/* Show additional absorbed finding types */}
                                                    {finding.details?.additional_finding_types?.map((addType: { type: string; severity: string }, idx: number) => (
                                                        <FindingTypeBadge key={idx} type={addType.type} />
                                                    ))}
                                                    {/* Show context indicators */}
                                                    {finding.details?.outdated_info && !finding.details?.additional_finding_types?.some((t: { type: string }) => t.type === 'outdated') && (
                                                        <FindingTypeBadge type="outdated" />
                                                    )}
                                                    {finding.details?.quality_info && !finding.details?.additional_finding_types?.some((t: { type: string }) => t.type === 'quality') && (
                                                        <FindingTypeBadge type="quality" />
                                                    )}
                                                </div>
                                            </TableCell>
                                            <TableCell className="p-4 align-middle text-sm text-muted-foreground">
                                                {finding.scanners?.join(', ') || 'Unknown'}
                                            </TableCell>
                                        </>
                                    )}
                                </TableRow>
                            )
                        })}
                        {rowVirtualizer.getVirtualItems().length > 0 && (
                            <tr style={{ height: `${rowVirtualizer.getTotalSize() - rowVirtualizer.getVirtualItems()[rowVirtualizer.getVirtualItems().length - 1].end}px` }}>
                                <td colSpan={6} />
                            </tr>
                        )}
                    </TableBody>
                </table>
            )}

            {selectedFinding && (
                <FindingDetailsModal 
                    finding={selectedFinding} 
                    projectId={projectId}
                    scanId={scanId}
                    scanContext={scanContext}
                    isOpen={!!selectedFinding} 
                    onClose={() => setSelectedFinding(null)} 
                    onSelectFinding={async (id) => {
                        // First try exact match by ID
                        let found = allRows.find(f => f.id === id);
                        
                        if (!found) {
                            // Handle OUTDATED-{component} format
                            if (id.startsWith("OUTDATED-")) {
                                const component = id.replace("OUTDATED-", "");
                                found = allRows.find(f => 
                                    f.type === "outdated" && 
                                    f.component?.toLowerCase() === component.toLowerCase()
                                );
                            }
                            // Handle QUALITY:{component}:{version} format
                            else if (id.startsWith("QUALITY:")) {
                                const parts = id.split(":");
                                if (parts.length >= 2) {
                                    const component = parts[1];
                                    const version = parts[2];
                                    found = allRows.find(f => 
                                        f.type === "quality" && 
                                        f.component?.toLowerCase() === component?.toLowerCase() &&
                                        (!version || f.version === version)
                                    );
                                }
                            }
                            // Handle LIC-{license} format
                            else if (id.startsWith("LIC-")) {
                                found = allRows.find(f => f.id === id || f.type === "license");
                            }
                            // Handle EOL-{component}-{cycle} format
                            else if (id.startsWith("EOL-")) {
                                const parts = id.replace("EOL-", "").split("-");
                                const component = parts[0];
                                found = allRows.find(f => 
                                    f.type === "eol" && 
                                    f.component?.toLowerCase() === component?.toLowerCase()
                                );
                            }
                            // Handle component:version format (vulnerabilities)
                            else if (id.includes(":") && !id.startsWith("AGG:")) {
                                const [component, version] = id.split(":");
                                found = allRows.find(f => 
                                    f.component?.toLowerCase() === component?.toLowerCase() && 
                                    f.version === version
                                );
                            }
                        }

                        // If not found in the currently loaded rows (e.g., switching between quality/security), fetch from API
                        if (!found) {
                            try {
                                if (id.startsWith("OUTDATED-")) {
                                    const component = id.replace("OUTDATED-", "")
                                    const res = await scanApi.getFindings(scanId, { type: 'outdated', search: component, skip: 0, limit: 200 })
                                    found = res.items.find(f => f.type === 'outdated' && f.component?.toLowerCase() === component.toLowerCase())
                                } else if (id.startsWith("QUALITY:")) {
                                    const parts = id.split(":")
                                    const component = parts[1]
                                    const version = parts[2]
                                    const res = await scanApi.getFindings(scanId, { type: 'quality', search: component, skip: 0, limit: 200 })
                                    found = res.items.find(f => f.type === 'quality' && f.component?.toLowerCase() === component?.toLowerCase() && (!version || f.version === version))
                                } else if (id.startsWith("LIC-")) {
                                    const res = await scanApi.getFindings(scanId, { type: 'license', search: id, skip: 0, limit: 200 })
                                    found = res.items.find(f => f.id === id) || res.items[0]
                                } else if (id.startsWith("EOL-")) {
                                    const component = id.replace("EOL-", "").split("-")[0]
                                    const res = await scanApi.getFindings(scanId, { type: 'eol', search: component, skip: 0, limit: 200 })
                                    found = res.items.find(f => f.type === 'eol' && f.component?.toLowerCase() === component?.toLowerCase())
                                } else if (id.includes(":") && !id.startsWith("AGG:")) {
                                    const [component, version] = id.split(":")
                                    const res = await scanApi.getFindings(scanId, { type: 'vulnerability', search: component, skip: 0, limit: 200 })
                                    found = res.items.find(f => f.type === 'vulnerability' && f.component?.toLowerCase() === component?.toLowerCase() && f.version === version)
                                } else {
                                    const res = await scanApi.getFindings(scanId, { search: id, skip: 0, limit: 200 })
                                    found = res.items.find(f => f.id === id) || res.items[0]
                                }
                            } catch {
                                // ignore; keep modal as-is
                            }
                        }
                        
                        if (found) setSelectedFinding(found);
                    }}
                />
            )}
        </div>
    )
}
