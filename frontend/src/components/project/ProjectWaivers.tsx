import { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useProjectWaivers, useDeleteWaiver, waiverKeys } from '@/hooks/queries/use-waivers'
import { Waiver } from '@/types/waiver'
import { useAuth } from '@/context/useAuth'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { getErrorMessage } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import { ArrowUp, ArrowDown, Trash2, Loader2 } from 'lucide-react'
import { formatDate } from '@/lib/utils'
import { toast } from "sonner"
import { useDebounce } from '@/hooks/use-debounce'
import { DEBOUNCE_DELAY_MS } from '@/lib/constants'

interface ProjectWaiversProps {
  projectId: string
}

export function ProjectWaivers({ projectId }: ProjectWaiversProps) {
    const queryClient = useQueryClient()
    const { hasPermission } = useAuth()

    const [searchInput, setSearchInput] = useState('')
    const [sortBy, setSortBy] = useState('created_at')
    const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
    const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
    const [waiverToDelete, setWaiverToDelete] = useState<Waiver | null>(null)

    const loadMoreRef = useRef<HTMLTableRowElement>(null)

    // Debounced search value
    const debouncedSearch = useDebounce(searchInput, DEBOUNCE_DELAY_MS)

    const {
        data,
        fetchNextPage,
        hasNextPage,
        isFetchingNextPage,
        isLoading,
    } = useProjectWaivers(projectId, { search: debouncedSearch, sortBy, sortOrder })

    const deleteWaiverMutation = useDeleteWaiver()

    // Flatten paginated data
    const allWaivers = useMemo(() => {
        if (!data?.pages) return []
        return data.pages.flatMap(page => page.items)
    }, [data])

    // Infinite scroll observer
    useEffect(() => {
        const observer = new IntersectionObserver(
            (entries) => {
                if (entries[0].isIntersecting && hasNextPage && !isFetchingNextPage) {
                    fetchNextPage()
                }
            },
            { threshold: 0.1 }
        )

        if (loadMoreRef.current) {
            observer.observe(loadMoreRef.current)
        }

        return () => observer.disconnect()
    }, [fetchNextPage, hasNextPage, isFetchingNextPage])

    const handleDelete = useCallback((id: string) => {
        deleteWaiverMutation.mutate(id, {
            onSuccess: () => {
                toast.success("Waiver deleted successfully")
                queryClient.invalidateQueries({ queryKey: waiverKeys.project(projectId) })
            },
            onError: (error) => {
                toast.error("Failed to delete waiver", {
                    description: getErrorMessage(error)
                })
            }
        })
    }, [deleteWaiverMutation, queryClient, projectId])

    const handleSort = (key: string) => {
        // Map UI keys to API keys
        const apiKey = key === 'expires' ? 'expiration_date' : key

        if (sortBy === apiKey) {
            setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
        } else {
            setSortBy(apiKey)
            setSortOrder('desc')
        }
    }

    const renderSortIcon = (key: string) => {
        const apiKey = key === 'expires' ? 'expiration_date' : key
        if (sortBy === apiKey) {
            return sortOrder === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
        }
        return null
    }

    if (isLoading) {
        return (
            <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
                    <div className="space-y-1">
                        <CardTitle>Active Waivers</CardTitle>
                        <CardDescription>Manage exceptions for security findings.</CardDescription>
                    </div>
                    <Skeleton className="h-10 w-[250px]" />
                </CardHeader>
                <CardContent>
                    <div className="space-y-2">
                        {Array.from({ length: 5 }).map((_, i) => (
                            <Skeleton key={i} className="h-12 w-full" />
                        ))}
                    </div>
                </CardContent>
            </Card>
        )
    }

    return (
        <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
                <div className="space-y-1">
                    <CardTitle>Active Waivers</CardTitle>
                    <CardDescription>Manage exceptions for security findings.</CardDescription>
                </div>
                <div className="w-[250px]">
                    <Input
                        placeholder="Search waivers..."
                        value={searchInput}
                        onChange={(e) => setSearchInput(e.target.value)}
                    />
                </div>
            </CardHeader>
            <CardContent>
                <div className="rounded-md border">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('finding_id')}>
                                    <div className="flex items-center gap-1">Finding ID {renderSortIcon('finding_id')}</div>
                                </TableHead>
                                <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('package_name')}>
                                    <div className="flex items-center gap-1">Package {renderSortIcon('package_name')}</div>
                                </TableHead>
                                <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('reason')}>
                                    <div className="flex items-center gap-1">Reason {renderSortIcon('reason')}</div>
                                </TableHead>
                                <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('expires')}>
                                    <div className="flex items-center gap-1">Expires {renderSortIcon('expires')}</div>
                                </TableHead>
                                <TableHead className="w-[80px]">Actions</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {allWaivers.map((waiver: Waiver) => (
                                <TableRow key={waiver.id}>
                                    <TableCell className="font-mono">{waiver.finding_id || "Any"}</TableCell>
                                    <TableCell>
                                        {waiver.package_name}
                                        {waiver.package_version && <span className="text-muted-foreground ml-1">v{waiver.package_version}</span>}
                                    </TableCell>
                                    <TableCell className="max-w-[300px] truncate" title={waiver.reason}>{waiver.reason}</TableCell>
                                    <TableCell>
                                        {waiver.expiration_date ? formatDate(waiver.expiration_date) : "Never"}
                                    </TableCell>
                                    <TableCell>
                                        {hasPermission('waiver:delete') && (
                                            <Button
                                                variant="ghost"
                                                size="icon"
                                                className="text-destructive hover:text-destructive hover:bg-destructive/10"
                                                onClick={() => {
                                                    setWaiverToDelete(waiver)
                                                    setDeleteDialogOpen(true)
                                                }}
                                                disabled={deleteWaiverMutation.isPending}
                                            >
                                                <Trash2 className="h-4 w-4" />
                                            </Button>
                                        )}
                                    </TableCell>
                                </TableRow>
                            ))}
                            {/* Infinite scroll trigger row */}
                            {hasNextPage && (
                                <TableRow ref={loadMoreRef}>
                                    <TableCell colSpan={5} className="text-center py-4">
                                        {isFetchingNextPage ? (
                                            <div className="flex items-center justify-center gap-2">
                                                <Loader2 className="h-4 w-4 animate-spin" />
                                                <span className="text-muted-foreground">Loading more...</span>
                                            </div>
                                        ) : (
                                            <span className="text-muted-foreground">Scroll to load more</span>
                                        )}
                                    </TableCell>
                                </TableRow>
                            )}
                            {allWaivers.length === 0 && !isLoading && (
                                <TableRow>
                                    <TableCell colSpan={5} className="text-center text-muted-foreground">
                                        No active waivers found.
                                    </TableCell>
                                </TableRow>
                            )}
                        </TableBody>
                    </Table>
                </div>
            </CardContent>

            <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Delete Waiver</DialogTitle>
                        <DialogDescription>
                            Are you sure you want to delete this waiver for{' '}
                            <strong>{waiverToDelete?.package_name}</strong>?
                            This action cannot be undone.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={() => {
                                if (waiverToDelete) {
                                    handleDelete(waiverToDelete.id)
                                    setDeleteDialogOpen(false)
                                    setWaiverToDelete(null)
                                }
                            }}
                            disabled={deleteWaiverMutation.isPending}
                        >
                            {deleteWaiverMutation.isPending ? "Deleting..." : "Delete"}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </Card>
    )
}
