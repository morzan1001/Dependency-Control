import { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useGlobalWaivers, useDeleteWaiver, waiverKeys } from '@/hooks/queries/use-waivers'
import { Waiver } from '@/types/waiver'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { getErrorMessage, formatDate } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { ArrowUp, ArrowDown, Pencil, Plus, Trash2, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { useDebounce } from '@/hooks/use-debounce'
import { DEBOUNCE_DELAY_MS } from '@/lib/constants'
import { EditWaiverDialog } from '@/components/waivers/EditWaiverDialog'
import { CreateGlobalWaiverDialog } from '@/components/waivers/CreateGlobalWaiverDialog'

export default function GlobalWaivers() {
    const queryClient = useQueryClient()

    const [searchInput, setSearchInput] = useState('')
    const [sortBy, setSortBy] = useState('created_at')
    const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
    const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
    const [waiverToDelete, setWaiverToDelete] = useState<Waiver | null>(null)
    const [editDialogOpen, setEditDialogOpen] = useState(false)
    const [waiverToEdit, setWaiverToEdit] = useState<Waiver | null>(null)
    const [createDialogOpen, setCreateDialogOpen] = useState(false)

    const loadMoreRef = useRef<HTMLTableRowElement>(null)
    const debouncedSearch = useDebounce(searchInput, DEBOUNCE_DELAY_MS)

    const {
        data,
        fetchNextPage,
        hasNextPage,
        isFetchingNextPage,
        isLoading,
    } = useGlobalWaivers({ search: debouncedSearch, sortBy, sortOrder })

    const deleteWaiverMutation = useDeleteWaiver()

    const allWaivers = useMemo(() => {
        if (!data?.pages) return []
        return data.pages.flatMap(page => page.items)
    }, [data])

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
                toast.success('Waiver deleted successfully')
                queryClient.invalidateQueries({ queryKey: waiverKeys.all })
            },
            onError: (error) => {
                toast.error('Failed to delete waiver', {
                    description: getErrorMessage(error),
                })
            },
        })
    }, [deleteWaiverMutation, queryClient])

    const handleSort = (key: string) => {
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
            <div className="space-y-6">
                <div className="flex justify-between items-start">
                    <div>
                        <h1 className="text-3xl font-bold tracking-tight">Global Waivers</h1>
                        <p className="text-muted-foreground">Manage waivers that apply across all projects.</p>
                    </div>
                </div>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
                        <div className="space-y-1">
                            <CardTitle>Waivers</CardTitle>
                        </div>
                        <Skeleton className="h-10 w-[250px]" />
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-2">
                            {Array.from({ length: 5 }).map((_, i) => (
                                <Skeleton key={`skeleton-${i}`} className="h-12 w-full" />
                            ))}
                        </div>
                    </CardContent>
                </Card>
            </div>
        )
    }

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-start">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Global Waivers</h1>
                    <p className="text-muted-foreground">
                        Manage waivers that apply across all projects. Global waivers are applied during every scan.
                    </p>
                </div>
                <Button onClick={() => setCreateDialogOpen(true)}>
                    <Plus className="h-4 w-4 mr-2" />
                    Create Global Waiver
                </Button>
            </div>

            <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
                    <div className="space-y-1">
                        <CardTitle>Active Global Waivers</CardTitle>
                        <CardDescription>These waivers apply to all projects in the system.</CardDescription>
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
                                    <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('status')}>
                                        <div className="flex items-center gap-1">Status {renderSortIcon('status')}</div>
                                    </TableHead>
                                    <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('reason')}>
                                        <div className="flex items-center gap-1">Reason {renderSortIcon('reason')}</div>
                                    </TableHead>
                                    <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('expires')}>
                                        <div className="flex items-center gap-1">Expires {renderSortIcon('expires')}</div>
                                    </TableHead>
                                    <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('created_by')}>
                                        <div className="flex items-center gap-1">Created By {renderSortIcon('created_by')}</div>
                                    </TableHead>
                                    <TableHead className="w-[100px]">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {allWaivers.map((waiver: Waiver) => (
                                    <TableRow key={waiver.id}>
                                        <TableCell className="font-mono">
                                            <div className="flex items-center gap-1.5">
                                                {waiver.finding_id || 'Any'}
                                                {waiver.scope === 'file' && <Badge variant="secondary" className="text-[10px] px-1.5 py-0">Entire file</Badge>}
                                                {waiver.scope === 'rule' && <Badge variant="default" className="text-[10px] px-1.5 py-0">All files</Badge>}
                                            </div>
                                            {waiver.scope === 'rule' && waiver.rule_id && (
                                                <span className="text-[11px] text-muted-foreground">Rule: {waiver.rule_id}</span>
                                            )}
                                        </TableCell>
                                        <TableCell>
                                            {waiver.package_name || 'Any'}
                                            {waiver.package_version && <span className="text-muted-foreground ml-1">v{waiver.package_version}</span>}
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant={waiver.status === 'false_positive' ? 'outline' : 'secondary'}>
                                                {waiver.status === 'false_positive' ? 'False Positive' : 'Accepted Risk'}
                                            </Badge>
                                        </TableCell>
                                        <TableCell className="max-w-[250px] truncate" title={waiver.reason}>{waiver.reason}</TableCell>
                                        <TableCell>
                                            {waiver.expiration_date ? formatDate(waiver.expiration_date) : 'Never'}
                                        </TableCell>
                                        <TableCell className="text-muted-foreground text-xs">{waiver.created_by}</TableCell>
                                        <TableCell>
                                            <div className="flex items-center gap-1">
                                                <Button
                                                    variant="ghost"
                                                    size="icon"
                                                    onClick={() => {
                                                        setWaiverToEdit(waiver)
                                                        setEditDialogOpen(true)
                                                    }}
                                                >
                                                    <Pencil className="h-4 w-4" />
                                                </Button>
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
                                            </div>
                                        </TableCell>
                                    </TableRow>
                                ))}
                                {hasNextPage && (
                                    <TableRow ref={loadMoreRef}>
                                        <TableCell colSpan={7} className="text-center py-4">
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
                                        <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                                            No global waivers found.
                                        </TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </div>
                </CardContent>
            </Card>

            <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Delete Global Waiver</DialogTitle>
                        <DialogDescription>
                            Are you sure you want to delete this global waiver
                            {waiverToDelete?.package_name && <> for <strong>{waiverToDelete.package_name}</strong></>}?
                            This will affect all projects and cannot be undone.
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
                            {deleteWaiverMutation.isPending ? 'Deleting...' : 'Delete'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <EditWaiverDialog
                waiver={waiverToEdit}
                open={editDialogOpen}
                onOpenChange={setEditDialogOpen}
            />

            <CreateGlobalWaiverDialog
                open={createDialogOpen}
                onOpenChange={setCreateDialogOpen}
            />
        </div>
    )
}
