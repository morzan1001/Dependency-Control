import { useInfiniteQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useRef, useEffect } from 'react'
import { getScanFindings } from '@/lib/api'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'

interface FindingsTableProps {
    scanId: string;
    category?: string;
    search?: string;
}

export function FindingsTable({ scanId, category, search }: FindingsTableProps) {
    const parentRef = useRef<HTMLDivElement>(null)

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
        getScrollElement: () => parentRef.current,
        estimateSize: () => 60,
        overscan: 5,
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
        <div ref={parentRef} className="h-[600px] overflow-auto border rounded-md">
            <Table>
                <TableHeader className="sticky top-0 bg-background z-10">
                    <TableRow>
                        <TableHead>Severity</TableHead>
                        <TableHead>ID</TableHead>
                        <TableHead>Component</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Description</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody style={{ height: `${rowVirtualizer.getTotalSize()}px`, position: 'relative' }}>
                    {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                        const isLoaderRow = virtualRow.index > allRows.length - 1
                        const finding = allRows[virtualRow.index]

                        return (
                            <TableRow
                                key={virtualRow.index}
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
                                    <TableCell colSpan={5}>Loading more...</TableCell>
                                ) : (
                                    <>
                                        <TableCell>
                                            <SeverityBadge severity={finding.severity} />
                                        </TableCell>
                                        <TableCell className="font-mono text-xs">{finding.id}</TableCell>
                                        <TableCell>
                                            <div className="flex flex-col">
                                                <span className="font-medium">{finding.component}</span>
                                                <span className="text-xs text-muted-foreground">{finding.version}</span>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant="outline">{finding.type}</Badge>
                                        </TableCell>
                                        <TableCell className="max-w-[400px] truncate" title={finding.description}>
                                            {finding.description}
                                        </TableCell>
                                    </>
                                )}
                            </TableRow>
                        )
                    })}
                </TableBody>
            </Table>
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
