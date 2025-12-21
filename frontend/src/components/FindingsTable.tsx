import { useInfiniteQuery, keepPreviousData } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useRef, useEffect, useState, useLayoutEffect } from 'react'
import { getScanFindings, Finding } from '@/lib/api'
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { FindingDetailsModal } from '@/components/FindingDetailsModal'
import { ArrowUp, ArrowDown } from 'lucide-react';
import { DEFAULT_PAGE_SIZE, VIRTUAL_SCROLL_OVERSCAN } from '@/lib/constants';

interface FindingsTableProps {
    scanId: string;
    projectId: string;
    category?: string;
    search?: string;
}

export function FindingsTable({ scanId, projectId, category, search }: FindingsTableProps) {
    const parentRef = useRef<HTMLDivElement>(null)
    const [scrollContainer, setScrollContainer] = useState<HTMLElement | null>(null)
    const [tableOffset, setTableOffset] = useState(0)
    const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
    const [sortBy, setSortBy] = useState("severity")
    const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc")

    useLayoutEffect(() => {
        // Find the main scroll container
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
            const res = await getScanFindings(scanId, {
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

    const rowVirtualizer = useVirtualizer({
        count: hasNextPage ? allRows.length + 1 : allRows.length,
        getScrollElement: () => scrollContainer,
        estimateSize: () => 60,
        overscan: VIRTUAL_SCROLL_OVERSCAN,
        observeElementOffset: (_instance, cb) => {
            const element = scrollContainer
            if (!element) return undefined

            const onScroll = () => {
                const offset = element.scrollTop - tableOffset
                cb(Math.max(0, offset), false)
            }

            element.addEventListener('scroll', onScroll, { passive: true })
            onScroll()
            return () => {
                element.removeEventListener('scroll', onScroll)
            }
        },
    })

    const virtualItems = rowVirtualizer.getVirtualItems()
    const lastItemIndex = virtualItems.length > 0 ? virtualItems[virtualItems.length - 1]?.index : -1

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

    if (isLoading) {
        return (
            <div className="relative">
                <table className="w-full text-sm table-fixed">
                    <TableHeader className="sticky top-0 bg-background z-50 shadow-sm">
                        <TableRow className="w-full">
                            <TableHead className="w-[100px] bg-background">Severity</TableHead>
                            <TableHead className="w-[180px] bg-background">ID</TableHead>
                            <TableHead className="w-auto bg-background">Component</TableHead>
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
                                <TableCell className="p-4"><Skeleton className="h-6 w-20" /></TableCell>
                                <TableCell className="p-4"><Skeleton className="h-6 w-20" /></TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </table>
            </div>
        )
    }

    if (isError) return <div>Error loading findings</div>

    if (allRows.length === 0) return <div className="p-4 text-center text-muted-foreground">No findings found</div>

    return (
        <div ref={parentRef} className="relative w-full">
            <table className="w-full caption-bottom text-sm table-fixed">
                <TableHeader className="sticky top-0 bg-background z-50 shadow-sm">
                    <TableRow className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
                        <TableHead className="w-[100px] h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground bg-background" onClick={() => handleSort('severity')}>
                            Severity {renderSortIcon('severity')}
                        </TableHead>
                        <TableHead className="w-[180px] h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground bg-background" onClick={() => handleSort('vuln_id')}>
                            ID {renderSortIcon('vuln_id')}
                        </TableHead>
                        <TableHead className="w-auto h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground bg-background" onClick={() => handleSort('component')}>
                            Component {renderSortIcon('component')}
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
                            <td colSpan={5} />
                        </tr>
                    )}
                    {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                        const isLoaderRow = virtualRow.index > allRows.length - 1
                        const finding = allRows[virtualRow.index]

                        return (
                            <TableRow
                                onClick={() => !isLoaderRow && setSelectedFinding(finding)}
                                key={virtualRow.index}
                                data-index={virtualRow.index}
                                ref={rowVirtualizer.measureElement}
                                className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted cursor-pointer"
                            >
                                {isLoaderRow ? (
                                    <TableCell colSpan={5} className="p-4 text-center">Loading more...</TableCell>
                                ) : (
                                    <>
                                        <TableCell className="p-4 align-middle">
                                            <SeverityBadge severity={finding.severity} />
                                        </TableCell>
                                        <TableCell className="p-4 align-middle font-mono text-xs truncate" title={finding.id}>
                                            {finding.type === 'vulnerability' && finding.details?.vulnerabilities?.length > 1 
                                                ? 'Multiple Vulnerabilities' 
                                                : (finding.type === 'vulnerability' && finding.details?.vulnerabilities?.length === 1 
                                                    ? finding.details.vulnerabilities[0].id 
                                                    : finding.id)}
                                        </TableCell>
                                        <TableCell className="p-4 align-middle">
                                            <div className="flex flex-col truncate">
                                                <span className="font-medium truncate" title={finding.component}>{finding.component}</span>
                                                <span className="text-xs text-muted-foreground truncate" title={finding.version}>{finding.version}</span>
                                            </div>
                                        </TableCell>
                                        <TableCell className="p-4 align-middle">
                                            <Badge variant="outline">{finding.type}</Badge>
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
                            <td colSpan={5} />
                        </tr>
                    )}
                </TableBody>
            </table>
            {selectedFinding && (
                <FindingDetailsModal 
                    finding={selectedFinding} 
                    projectId={projectId}
                    isOpen={!!selectedFinding} 
                    onClose={() => setSelectedFinding(null)} 
                    onSelectFinding={(id) => {
                        const found = allRows.find(f => f.id === id);
                        if (found) setSelectedFinding(found);
                    }}
                />
            )}
        </div>
    )
}

function SeverityBadge({ severity }: { severity: string }) {
    const color = {
        CRITICAL: "bg-red-500",
        HIGH: "bg-orange-500",
        MEDIUM: "bg-yellow-500",
        LOW: "bg-blue-500",
        INFO: "bg-gray-500",
        UNKNOWN: "bg-gray-400"
    }[severity] || "bg-gray-400"

    return <Badge className={`${color} hover:${color} text-white`}>{severity}</Badge>
}
