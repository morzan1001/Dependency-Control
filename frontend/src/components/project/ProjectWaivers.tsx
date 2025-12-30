import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getWaivers, deleteWaiver, Waiver, ApiError } from '@/lib/api'
import { useAuth } from '@/context/useAuth'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { ArrowUp, ArrowDown, Trash2 } from 'lucide-react'
import { toast } from "sonner"

interface ProjectWaiversProps {
  projectId: string
}

export function ProjectWaivers({ projectId }: ProjectWaiversProps) {
    const queryClient = useQueryClient()
    const { hasPermission } = useAuth()
    const { data: waivers, isLoading } = useQuery({
        queryKey: ['waivers', projectId],
        queryFn: () => getWaivers(projectId)
    })
    
    const [searchQuery, setSearchQuery] = useState('')
    const [sortConfig, setSortConfig] = useState<{ key: string, direction: 'asc' | 'desc' } | null>(null)

    const deleteWaiverMutation = useMutation({
        mutationFn: deleteWaiver,
        onSuccess: () => {
            toast.success("Waiver deleted successfully")
            queryClient.invalidateQueries({ queryKey: ['waivers', projectId] })
        },
        onError: (error: ApiError) => {
            toast.error("Failed to delete waiver", {
                description: error.response?.data?.detail || "An error occurred"
            })
        }
    })

    const filteredWaivers = useMemo(() => {
        if (!waivers) return []
        let result = [...waivers]
        
        if (searchQuery) {
            const lower = searchQuery.toLowerCase()
            result = result.filter((w: Waiver) => 
                (w.package_name || '').toLowerCase().includes(lower) ||
                (w.reason || '').toLowerCase().includes(lower) ||
                (w.finding_id || '').toLowerCase().includes(lower)
            )
        }

        if (sortConfig) {
            result.sort((a: Waiver, b: Waiver) => {
                let aValue: string | number | null | undefined = a[sortConfig.key as keyof Waiver] as string | undefined
                let bValue: string | number | null | undefined = b[sortConfig.key as keyof Waiver] as string | undefined
                
                if (sortConfig.key === 'expires') {
                    aValue = a.expiration_date ? new Date(a.expiration_date).getTime() : 9999999999999
                    bValue = b.expiration_date ? new Date(b.expiration_date).getTime() : 9999999999999
                }

                if ((aValue ?? '') < (bValue ?? '')) return sortConfig.direction === 'asc' ? -1 : 1
                if ((aValue ?? '') > (bValue ?? '')) return sortConfig.direction === 'asc' ? 1 : -1
                return 0
            })
        }
        return result
    }, [waivers, searchQuery, sortConfig])

    const requestSort = (key: string) => {
        let direction: 'asc' | 'desc' = 'asc'
        if (sortConfig && sortConfig.key === key && sortConfig.direction === 'asc') {
            direction = 'desc'
        }
        setSortConfig({ key, direction })
    }

    const renderSortIcon = (key: string) => {
        if (sortConfig?.key === key) {
            return sortConfig.direction === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
        }
        return null
    }

    if (isLoading) {
        return (
            <div className="space-y-4">
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
            </div>
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
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                </div>
            </CardHeader>
            <CardContent>
                <div className="relative w-full overflow-auto">
                    <table className="w-full caption-bottom text-sm">
                        <thead className="[&_tr]:border-b">
                            <tr className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground" onClick={() => requestSort('finding_id')}>
                                    <div className="flex items-center gap-1">Finding ID {renderSortIcon('finding_id')}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground" onClick={() => requestSort('package_name')}>
                                    <div className="flex items-center gap-1">Package {renderSortIcon('package_name')}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground" onClick={() => requestSort('reason')}>
                                    <div className="flex items-center gap-1">Reason {renderSortIcon('reason')}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground" onClick={() => requestSort('expires')}>
                                    <div className="flex items-center gap-1">Expires {renderSortIcon('expires')}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="[&_tr:last-child]:border-0">
                            {filteredWaivers.map((waiver: Waiver) => (
                                <tr key={waiver.id} className="border-b transition-colors hover:bg-muted/50">
                                    <td className="p-4 align-middle font-mono">{waiver.finding_id || "Any"}</td>
                                    <td className="p-4 align-middle">
                                        {waiver.package_name} 
                                        {waiver.package_version && <span className="text-muted-foreground ml-1">v{waiver.package_version}</span>}
                                    </td>
                                    <td className="p-4 align-middle max-w-[300px] truncate" title={waiver.reason}>{waiver.reason}</td>
                                    <td className="p-4 align-middle">
                                        {waiver.expiration_date ? new Date(waiver.expiration_date).toLocaleDateString() : "Never"}
                                    </td>
                                    <td className="p-4 align-middle">
                                        {hasPermission('waiver:delete') && (
                                            <Button 
                                                variant="ghost" 
                                                size="icon" 
                                                className="text-destructive hover:text-destructive hover:bg-destructive/10"
                                                onClick={() => {
                                                    if (confirm("Are you sure you want to delete this waiver?")) {
                                                        deleteWaiverMutation.mutate(waiver.id)
                                                    }
                                                }}
                                                disabled={deleteWaiverMutation.isPending}
                                            >
                                                <Trash2 className="h-4 w-4" />
                                            </Button>
                                        )}
                                    </td>
                                </tr>
                            ))}
                            {filteredWaivers.length === 0 && (
                                <tr>
                                    <td colSpan={5} className="p-4 text-center text-muted-foreground">No active waivers found.</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </CardContent>
        </Card>
    )
}
