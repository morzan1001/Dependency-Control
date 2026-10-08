import { useEffect, useRef, useState } from 'react'
import { useWaiverList, useDeleteWaiver } from '@/hooks/queries/use-waivers'
import { Waiver } from '@/types/waiver'
import { EditWaiverDialog } from '@/components/waivers/EditWaiverDialog'
import { WaiverExpiryCell } from '@/components/waivers/WaiverExpiryCell'
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
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { ArrowUp, ArrowDown, Pencil, Trash2, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { useDebounce } from '@/hooks/use-debounce'
import { DEBOUNCE_DELAY_MS } from '@/lib/constants'

interface WaiverListProps {
    projectId?: string
    canEdit?: boolean
    canDelete?: boolean
}

export function WaiverList({ projectId, canEdit = true, canDelete = true }: Readonly<WaiverListProps>) {
    const isGlobal = !projectId
    const columns = isGlobal ? 7 : 6
    const [searchInput, setSearchInput] = useState('')
    const [orphanedOnly, setOrphanedOnly] = useState(false)
    const [sortBy, setSortBy] = useState('created_at')
    const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
    const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
    const [waiverToDelete, setWaiverToDelete] = useState<Waiver | null>(null)
    const [waiverToEdit, setWaiverToEdit] = useState<Waiver | null>(null)
    const [editDialogOpen, setEditDialogOpen] = useState(false)

    const loadMoreRef = useRef<HTMLTableRowElement>(null)
    const debouncedSearch = useDebounce(searchInput, DEBOUNCE_DELAY_MS)

    const { data, fetchNextPage, hasNextPage, isFetchingNextPage, isLoading, isError } = useWaiverList(
        projectId,
        { search: debouncedSearch, sortBy, sortOrder, orphaned: orphanedOnly },
    )
    const deleteWaiverMutation = useDeleteWaiver()
    const allWaivers = data?.pages.flatMap((page) => page.items) ?? []

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

    const handleDelete = (id: string) => {
        deleteWaiverMutation.mutate(id, {
            onSuccess: () => toast.success('Waiver deleted successfully'),
            onError: (error) => toast.error('Failed to delete waiver', { description: getErrorMessage(error) }),
        })
    }

    const apiSortKey = (key: string) => (key === 'expires' ? 'expiration_date' : key)

    const handleSort = (key: string) => {
        const apiKey = apiSortKey(key)
        if (sortBy === apiKey) {
            setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
        } else {
            setSortBy(apiKey)
            setSortOrder('desc')
        }
    }

    const sortableHead = (key: string, label: string) => (
        <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort(key)}>
            <div className="flex items-center gap-1">
                {label}{' '}
                {sortBy === apiSortKey(key) && (sortOrder === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />)}
            </div>
        </TableHead>
    )

    const title = isGlobal ? 'Active Global Waivers' : 'Active Waivers'
    const description = isGlobal
        ? 'These waivers apply to all projects in the system.'
        : 'Manage exceptions for security findings.'

    if (isLoading) {
        return (
            <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
                    <div className="space-y-1">
                        <CardTitle>{title}</CardTitle>
                        <CardDescription>{description}</CardDescription>
                    </div>
                    <Skeleton className="h-10 w-[370px]" />
                </CardHeader>
                <CardContent>
                    <div className="space-y-2">
                        {['s1', 's2', 's3', 's4', 's5'].map((skeletonId) => (
                            <Skeleton key={skeletonId} className="h-12 w-full" />
                        ))}
                    </div>
                </CardContent>
            </Card>
        )
    }

    let emptyText = isGlobal ? 'No global waivers found.' : 'No active waivers found.'
    if (orphanedOnly) emptyText = 'No orphaned waivers found.'
    if (debouncedSearch) emptyText = 'No waivers match your search.'

    return (
        <Card>
            <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between space-y-0 pb-4">
                <div className="space-y-1">
                    <CardTitle>{title}</CardTitle>
                    <CardDescription>{description}</CardDescription>
                </div>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                    <Label htmlFor="waivers-orphaned-only" className="flex items-center gap-2 text-sm cursor-pointer whitespace-nowrap">
                        <Checkbox
                            id="waivers-orphaned-only"
                            checked={orphanedOnly}
                            onCheckedChange={(checked) => setOrphanedOnly(checked === true)}
                        />
                        Only orphaned
                    </Label>
                    <div className="w-full sm:w-[250px]">
                        <Input
                            placeholder="Search waivers..."
                            value={searchInput}
                            onChange={(e) => setSearchInput(e.target.value)}
                        />
                    </div>
                </div>
            </CardHeader>
            <CardContent>
                <div className="rounded-md border">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                {sortableHead('finding_id', 'Finding ID')}
                                {sortableHead('package_name', 'Package')}
                                {sortableHead('status', 'Status')}
                                {sortableHead('reason', 'Reason')}
                                {sortableHead('expires', 'Expires')}
                                {isGlobal && sortableHead('created_by', 'Created By')}
                                <TableHead className="w-[100px]">Actions</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {allWaivers.map((waiver) => (
                                <TableRow key={waiver.id}>
                                    <TableCell className="font-mono">
                                        <div className="flex items-center gap-1.5">
                                            <span className="truncate max-w-[220px]" title={waiver.vulnerability_id || waiver.finding_id || 'Any'}>{waiver.vulnerability_id || waiver.finding_id || 'Any'}</span>
                                            {waiver.scope === 'file' && <Badge variant="secondary" className="text-[10px] px-1.5 py-0 shrink-0">Entire file</Badge>}
                                            {waiver.scope === 'rule' && <Badge variant="default" className="text-[10px] px-1.5 py-0 shrink-0">All files</Badge>}
                                        </div>
                                        {waiver.scope === 'rule' && waiver.rule_id && (
                                            <span className="block truncate max-w-[260px] text-[11px] text-muted-foreground" title={waiver.rule_id}>Rule: {waiver.rule_id}</span>
                                        )}
                                    </TableCell>
                                    <TableCell>
                                        <div className="max-w-[240px] truncate" title={waiver.package_name || 'Any'}>
                                            {waiver.package_name || 'Any'}
                                            {waiver.package_version && <span className="text-muted-foreground ml-1">v{waiver.package_version}</span>}
                                        </div>
                                    </TableCell>
                                    <TableCell>
                                        <Badge variant={waiver.status === 'false_positive' ? 'outline' : 'secondary'}>
                                            {waiver.status === 'false_positive' ? 'False Positive' : 'Accepted Risk'}
                                        </Badge>
                                        {waiver.is_active && waiver.last_eval_scan_id != null && waiver.last_match_count === 0 && (
                                            <Badge
                                                variant="outline"
                                                title="This waiver suppresses no finding in the latest scan — the code location is gone or the rule was renamed. Review or re-waive."
                                                className="ml-1 text-[10px] border-amber-400 bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-600 w-fit whitespace-nowrap"
                                            >
                                                Matches nothing
                                            </Badge>
                                        )}
                                    </TableCell>
                                    <TableCell><div className="max-w-[300px] truncate" title={waiver.reason}>{waiver.reason}</div></TableCell>
                                    <TableCell>
                                        <WaiverExpiryCell waiver={waiver} />
                                    </TableCell>
                                    {isGlobal && <TableCell className="text-muted-foreground text-xs">{waiver.created_by}</TableCell>}
                                    <TableCell>
                                        <div className="flex items-center gap-1">
                                            {canEdit && (
                                                <Button
                                                    variant="ghost"
                                                    size="icon"
                                                    aria-label="Edit waiver"
                                                    onClick={() => {
                                                        setWaiverToEdit(waiver)
                                                        setEditDialogOpen(true)
                                                    }}
                                                >
                                                    <Pencil className="h-4 w-4" />
                                                </Button>
                                            )}
                                            {canDelete && (
                                                <Button
                                                    variant="ghost"
                                                    size="icon"
                                                    aria-label="Delete waiver"
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
                                        </div>
                                    </TableCell>
                                </TableRow>
                            ))}
                            {hasNextPage && (
                                <TableRow ref={loadMoreRef}>
                                    <TableCell colSpan={columns} className="text-center py-4">
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
                            {isError && (
                                <TableRow>
                                    <TableCell colSpan={columns} className="text-center text-destructive py-8">
                                        Failed to load waivers. Please try again.
                                    </TableCell>
                                </TableRow>
                            )}
                            {allWaivers.length === 0 && !isError && (
                                <TableRow>
                                    <TableCell colSpan={columns} className="text-center text-muted-foreground py-8">
                                        {emptyText}
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
                        <DialogTitle>{isGlobal ? 'Delete Global Waiver' : 'Delete Waiver'}</DialogTitle>
                        <DialogDescription>
                            {isGlobal ? 'Are you sure you want to delete this global waiver' : 'Are you sure you want to delete this waiver'}
                            {waiverToDelete?.package_name && <> for <strong className="break-all">{waiverToDelete.package_name}</strong></>}?
                            {isGlobal ? ' This will affect all projects and cannot be undone.' : ' This action cannot be undone.'}
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={() => {
                                if (waiverToDelete) handleDelete(waiverToDelete.id)
                                setDeleteDialogOpen(false)
                                setWaiverToDelete(null)
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
        </Card>
    )
}
