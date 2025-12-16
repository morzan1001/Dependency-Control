import { useInfiniteQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useRef, useEffect, useState, useLayoutEffect } from 'react'
import { getScanFindings, Finding } from '@/lib/api'
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { FindingDetailsModal } from '@/components/FindingDetailsModal'

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

    useLayoutEffect(() => {
        if (!parentRef.current) return
        
        const container = parentRef.current.closest('main') as HTMLElement
        setScrollContainer(container)

        if (container) {
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
        queryKey: ['findings', scanId, category, search],
        queryFn: async ({ pageParam = 0 }) => {
            const res = await getScanFindings(scanId, {
                skip: pageParam,
                limit: 50,
                category,
                search
            });
            return res;
        },
        initialPageParam: 0,
        getNextPageParam: (lastPage) => {
            const nextSkip = (lastPage.page * lastPage.size);
            return nextSkip < lastPage.total ? nextSkip : undefined;
        }
    })

    const allRows = data ? data.pages.flatMap((d) => d.items) : []

    const rowVirtualizer = useVirtualizer({
        count: hasNextPage ? allRows.length + 1 : allRows.length,
        getScrollElement: () => scrollContainer,
        estimateSize: () => 60,
        overscan: 5,
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

    useEffect(() => {
        const [lastItem] = [...rowVirtualizer.getVirtualItems()].reverse()
        if (!lastItem) {
            return
        }

        if (
            lastItem.index >= allRows.length - 1 &&
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
        rowVirtualizer.getVirtualItems(),
    ])

    if (isLoading) return <div className="space-y-2">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
    </div>

    if (isError) return <div>Error loading findings</div>

    if (allRows.length === 0) return <div className="p-4 text-center text-muted-foreground">No findings found</div>

    return (
        <div ref={parentRef} className="relative">
            <table className="w-full text-sm">
                <TableHeader className="sticky top-0 bg-background z-10 shadow-sm">
                    <TableRow className="flex w-full">
                        <TableHead className="w-[100px] flex-none">Severity</TableHead>
                        <TableHead className="w-[150px] flex-none">ID</TableHead>
                        <TableHead className="w-[200px] flex-none">Component</TableHead>
                        <TableHead className="w-[120px] flex-none">Type</TableHead>
                        <TableHead className="w-[120px] flex-none">Scanner</TableHead>
                        <TableHead className="flex-1">Description</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody style={{ height: `${rowVirtualizer.getTotalSize()}px`, position: 'relative', display: 'block' }}>
                    {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                        const isLoaderRow = virtualRow.index > allRows.length - 1
                        const finding = allRows[virtualRow.index]

                        return (
                            <TableRow
                                onClick={() => !isLoaderRow && setSelectedFinding(finding)}
                                key={virtualRow.index}
                                className="cursor-pointer hover:bg-muted/50 flex w-full border-b"
                                style={{
                                    position: 'absolute',
                                    top: 0,
                                    left: 0,
                                    width: '100%',
                                    height: `${virtualRow.size}px`,
                                    transform: `translateY(${virtualRow.start}px)`,
                                }}
                            >
                                {isLoaderRow ? (
                                    <TableCell colSpan={6} className="w-full text-center">Loading more...</TableCell>
                                ) : (
                                    <>
                                        <TableCell className="w-[100px] flex-none">
                                            <SeverityBadge severity={finding.severity} />
                                        </TableCell>
                                        <TableCell className="w-[150px] flex-none font-mono text-xs truncate" title={finding.id}>
                                            {finding.id}
                                        </TableCell>
                                        <TableCell className="w-[200px] flex-none">
                                            <div className="flex flex-col truncate">
                                                <span className="font-medium truncate" title={finding.component}>{finding.component}</span>
                                                <span className="text-xs text-muted-foreground truncate" title={finding.version}>{finding.version}</span>
                                            </div>
                                        </TableCell>
                                        <TableCell className="w-[120px] flex-none">
                                            <Badge variant="outline">{finding.type}</Badge>
                                        </TableCell>
                                        <TableCell className="w-[120px] flex-none text-sm text-muted-foreground">
                                            {finding.scanners?.join(', ') || 'Unknown'}
                                        </TableCell>
                                        <TableCell className="flex-1 truncate" title={finding.description}>
                                            {finding.description}
                                        </TableCell>
                                    </>
                                )}
                            </TableRow>
                        )
                    })}
                </TableBody>
            </table>
            {selectedFinding && (
                <FindingDetailsModal 
                    finding={selectedFinding} 
                    projectId={projectId}
                    isOpen={!!selectedFinding} 
                    onClose={() => setSelectedFinding(null)} 
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
