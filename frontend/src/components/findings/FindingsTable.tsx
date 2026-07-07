import { useInfiniteQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { scanApi } from '@/api/scans'
import { Finding } from '@/types/scan'
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Skeleton } from '@/components/ui/skeleton'
import { InlineError, NoData } from '@/components/ui/state-components'
import { FindingDetailsModal } from './FindingDetailsModal'
import { ArrowUp, ArrowDown, Shield, AlertTriangle, Loader2 } from 'lucide-react';
import { DEFAULT_PAGE_SIZE } from '@/lib/constants';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from './SeverityBadge'
import { FindingTypeBadge } from './FindingTypeBadge'
import { getSourceInfo } from '@/lib/finding-utils'
import { ScanContext } from './details/SastDetailsView'
import { resolveRelatedFindingInRows, fetchRelatedFinding } from './related-finding-rows'

// Stable keys for the loading skeleton rows. Using fixed string keys avoids
// the "array index as key" anti-pattern while still rendering a stable list.
const SKELETON_ROW_KEYS = Array.from({ length: 10 }, (_, i) => `skeleton-row-${i}`)

// Sub-shape of `Finding.details` we touch when computing the display ID.
type FindingWithDetails = {
    id: string
    type?: string
    details?: {
        vulnerabilities?: ReadonlyArray<{ id?: string }>
        quality_issues?: ReadonlyArray<{ id?: string }>
    }
}

/**
 * Compute the user-visible ID for a finding row.
 *
 * Vulnerability and quality findings can aggregate multiple underlying issues;
 * we show "Multiple …" when there is more than one, the single issue's id when
 * there is exactly one, and otherwise fall back to the finding's own id.
 */
function getDisplayId(finding: FindingWithDetails): string | undefined {
    const vulnCount = finding.details?.vulnerabilities?.length ?? 0
    if (finding.type === 'vulnerability') {
        if (vulnCount > 1) return 'Multiple Vulnerabilities'
        if (vulnCount === 1) return finding.details?.vulnerabilities?.[0]?.id
    }
    const qualityCount = finding.details?.quality_issues?.length ?? 0
    if (finding.type === 'quality') {
        if (qualityCount > 1) return 'Multiple Quality Issues'
        if (qualityCount === 1) return finding.details?.quality_issues?.[0]?.id
    }
    return finding.id
}

interface ReachabilityIndicatorProps {
    readonly reachability: NonNullable<NonNullable<Finding['details']>['reachability']>
}

function ReachabilityIndicator({ reachability }: ReachabilityIndicatorProps) {
    const isReachable = reachability.is_reachable
    const containerClass = isReachable
        ? 'bg-red-100 text-severity-critical'
        : 'bg-green-100 text-success'
    const label = isReachable ? 'Reachable Code' : 'Not Reachable'
    return (
        <Tooltip>
            <TooltipTrigger asChild>
                <div className={`flex items-center justify-center w-5 h-5 rounded-full ${containerClass}`}>
                    {isReachable ? <AlertTriangle className="h-3 w-3" /> : <Shield className="h-3 w-3" />}
                </div>
            </TooltipTrigger>
            <TooltipContent side="right">
                <div className="space-y-1">
                    <p className="font-medium">{label}</p>
                    {reachability.analysis_level && (
                        <p className="text-xs">Analysis: {reachability.analysis_level}</p>
                    )}
                    {reachability.confidence_score && (
                        <p className="text-xs">
                            Confidence: {Math.round(reachability.confidence_score * 100)}%
                        </p>
                    )}
                </div>
            </TooltipContent>
        </Tooltip>
    )
}

type SourceInfo = NonNullable<ReturnType<typeof getSourceInfo>>

interface SourceCellProps {
    readonly finding: Finding
    readonly sourceInfo: SourceInfo | null
}

function SourceCell({ finding, sourceInfo }: SourceCellProps) {
    if (!sourceInfo) {
        return <span className="text-muted-foreground text-center block">-</span>
    }
    const directLabel = finding.direct ? 'Direct dependency' : 'Transitive dependency'
    const inferredSuffix = finding.direct_inferred ? ' (inferred)' : ''
    return (
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
                        <div className="space-y-0.5">
                            <p className="text-xs">{directLabel}{inferredSuffix}</p>
                            {finding.direct_inferred && (
                                <p className="text-xs text-muted-foreground italic">
                                    Classification inferred (SBOM had no dependency graph)
                                </p>
                            )}
                        </div>
                    )}
                </div>
            </TooltipContent>
        </Tooltip>
    )
}

interface TypeBadgesProps {
    readonly finding: Finding
}

function TypeBadges({ finding }: TypeBadgesProps) {
    const additionalTypes = finding.details?.additional_finding_types ?? []
    const hasAdditional = (type: string) =>
        additionalTypes.some((t: { type: string }) => t.type === type)
    return (
        <div className="flex flex-wrap gap-1">
            <FindingTypeBadge type={finding.type} />
            {additionalTypes.map((addType: { type: string; severity: string }) => (
                <FindingTypeBadge key={addType.type} type={addType.type} />
            ))}
            {finding.details?.outdated_info && !hasAdditional('outdated') && (
                <FindingTypeBadge type="outdated" />
            )}
            {finding.details?.quality_info && !hasAdditional('quality') && (
                <FindingTypeBadge type="quality" />
            )}
        </div>
    )
}

interface FindingsTableProps {
    readonly scanId: string;
    readonly projectId: string;
    readonly category?: string;
    readonly search?: string;
    readonly severity?: string;
    readonly scanContext?: ScanContext;
    /** Top offset (px) for the sticky table header, e.g. when a sticky TabsList sits above. */
    readonly stickyHeaderTop?: number;
    /** Filter by license category (e.g. weak_copyleft, strong_copyleft) */
    readonly licenseCategory?: string;
    /** Hide INFO-level findings */
    readonly hideInfo?: boolean;
    /**
     * Which side of the active/waived split this table shows.
     * - "active" (default): only un-waived findings — the main list users care about.
     * - "waived": only waived findings — used for the secondary "what is being suppressed" list.
     * - "all": both. Kept as an escape hatch; not used by the standard scan view.
     */
    readonly waivedFilter?: "active" | "waived" | "all";
}

export function FindingsTable({ scanId, projectId, category, search, severity, scanContext, stickyHeaderTop = 0, licenseCategory, hideInfo, waivedFilter = "active" }: FindingsTableProps) {
    const sentinelRef = useRef<HTMLDivElement>(null)
    const scrollTargetRef = useRef<HTMLTableRowElement | null>(null)
    const hasScrolledRef = useRef(false)
    const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
    const [sortBy, setSortBy] = useState("severity")
    const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc")
    const [searchParams, setSearchParams] = useSearchParams()
    const deepLinkFindingId = searchParams.get('finding')
    // Guard so we only auto-open once per deep-link value — otherwise the
    // effect would re-trigger every time selectedFinding changes.
    const openedDeepLinkRef = useRef<string | null>(null)

    useEffect(() => {
        if (!deepLinkFindingId) {
            openedDeepLinkRef.current = null
            return
        }
        if (openedDeepLinkRef.current === deepLinkFindingId) return
        let cancelled = false
        ;(async () => {
            try {
                // Try the internal UUID first (what the backend emits as .id),
                // fall back to the stable finding_id string (e.g. "CVE-X").
                const res = await scanApi.getFindings(scanId, { search: deepLinkFindingId, skip: 0, limit: 200 })
                let found = res.items.find(f => f.id === deepLinkFindingId)
                    || res.items.find(f => (f as { finding_id?: string }).finding_id === deepLinkFindingId)
                if (!found && res.items.length === 1) found = res.items[0]
                if (!cancelled && found) {
                    openedDeepLinkRef.current = deepLinkFindingId
                    setSelectedFinding(found)
                }
            } catch (err) {
                console.error('Failed to open deep-linked finding:', err)
            }
        })()
        return () => { cancelled = true }
    }, [deepLinkFindingId, scanId])

    // Strip the ?finding=… param once the user closes the drawer so the
    // deep-link doesn't immediately reopen it.
    const closeSelectedFinding = () => {
        setSelectedFinding(null)
        if (searchParams.has('finding')) {
            setSearchParams(prev => {
                prev.delete('finding')
                return prev
            }, { replace: true })
        }
    }

    const {
        data,
        fetchNextPage,
        hasNextPage,
        isFetchingNextPage,
        isLoading,
        isError
    } = useInfiniteQuery({
        // severity is NOT passed to API - we show all findings but scroll to the target
        queryKey: ['findings', scanId, category, search, sortBy, sortOrder, licenseCategory, hideInfo, waivedFilter],
        queryFn: async ({ pageParam = 0 }) => {
            const res = await scanApi.getFindings(scanId, {
                skip: pageParam,
                limit: DEFAULT_PAGE_SIZE,
                category,
                search,
                sort_by: sortBy,
                sort_order: sortOrder,
                ...(licenseCategory ? { license_category: licenseCategory } : {}),
                ...(hideInfo ? { hide_info: true } : {}),
                // "all" is the escape hatch — omit the param so the backend
                // returns both waived and active findings.
                ...(waivedFilter === "active" ? { waived: false } : {}),
                ...(waivedFilter === "waived" ? { waived: true } : {}),
            });
            return res;
        },
        initialPageParam: 0,
        getNextPageParam: (lastPage, allPages) => {
            const totalLoaded = allPages.reduce((sum, page) => sum + page.items.length, 0);
            return totalLoaded < lastPage.total ? totalLoaded : undefined;
        },
    })

    const allRows = data ? data.pages.flatMap((d) => d.items) : []

    // Derive the scroll-target row index purely from props/data (no ref reads
    // during render). `hasScrolledRef` is only consulted inside the effect
    // below to guarantee we scroll at most once per mount.
    const scrollTargetIndex = severity
        ? allRows.findIndex(f => f.severity?.toUpperCase() === severity.toUpperCase())
        : -1

    // Scroll to first finding matching the target severity (from URL param)
    useEffect(() => {
        if (!severity || hasScrolledRef.current || scrollTargetIndex < 0) return
        const targetRow = scrollTargetRef.current
        if (targetRow) {
            targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' })
            targetRow.classList.add('ring-2', 'ring-primary', 'ring-offset-1')
            setTimeout(() => targetRow.classList.remove('ring-2', 'ring-primary', 'ring-offset-1'), 3000)
            hasScrolledRef.current = true
        }
    }, [severity, scrollTargetIndex])

    // IntersectionObserver on sentinel element triggers loading the next page
    // when the user scrolls near the bottom of the table.
    useEffect(() => {
        const sentinel = sentinelRef.current
        if (!sentinel) return

        const observer = new IntersectionObserver(
            (entries) => {
                if (entries[0].isIntersecting && hasNextPage && !isFetchingNextPage) {
                    fetchNextPage()
                }
            },
            { rootMargin: '300px' }
        )
        observer.observe(sentinel)
        return () => observer.disconnect()
    }, [hasNextPage, isFetchingNextPage, fetchNextPage])

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
        <div className="relative w-full">
            {isLoading && (
                <div className="relative">
                    <table className="w-full text-sm table-fixed">
                        <TableHeader className="sticky bg-background z-50 shadow-sm" style={{ top: stickyHeaderTop }}>
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
                            {SKELETON_ROW_KEYS.map((key) => (
                                <TableRow key={key} className="w-full border-b">
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
            )}
            {!isLoading && isError && (
                <InlineError message="Error loading findings" />
            )}
            {!isLoading && !isError && allRows.length === 0 && (
                <NoData entityName="findings" />
            )}
            {!isLoading && !isError && allRows.length > 0 && (
                <TooltipProvider>
                <table className="w-full caption-bottom text-sm table-fixed">
                    <TableHeader className="sticky bg-background z-50 shadow-sm" style={{ top: stickyHeaderTop }}>
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
                        {allRows.map((finding, index) => {
                            const sourceInfo = getSourceInfo(finding?.source_type)
                            // Attach the scroll-to ref to the first row whose severity matches
                            // the URL param. The index is derived purely from `allRows` above
                            // (no ref reads during render).
                            const isScrollTarget = index === scrollTargetIndex
                            const rowClass = `border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted cursor-pointer ${
                                finding.type === 'system_warning' ? 'bg-destructive/5 hover:bg-destructive/10 border-l-2 border-l-destructive' : ''
                            }`
                            return (
                                <TableRow
                                    ref={isScrollTarget ? scrollTargetRef : undefined}
                                    onClick={() => setSelectedFinding(finding)}
                                    key={finding.id}
                                    className={rowClass}
                                >
                                    <TableCell className="p-4 align-middle">
                                        <div className="flex items-center gap-1.5">
                                            <SeverityBadge severity={finding.severity} />
                                            {finding.details?.reachability && (
                                                <ReachabilityIndicator reachability={finding.details.reachability} />
                                            )}
                                        </div>
                                    </TableCell>
                                    <TableCell className="p-4 align-middle font-mono text-xs truncate" title={finding.id}>
                                        {getDisplayId(finding)}
                                    </TableCell>
                                    <TableCell className="p-4 align-middle">
                                        <div className="flex flex-col truncate">
                                            <span className="font-medium truncate" title={finding.component}>{finding.component}</span>
                                            <span className="text-xs text-muted-foreground truncate" title={finding.version}>{finding.version}</span>
                                        </div>
                                    </TableCell>
                                    <TableCell className="p-4 align-middle">
                                        <SourceCell finding={finding} sourceInfo={sourceInfo} />
                                    </TableCell>
                                    <TableCell className="p-4 align-middle">
                                        <div className="flex flex-col gap-1">
                                            <TypeBadges finding={finding} />
                                            {finding.waiver_lapsed && !finding.waived && (
                                                <Badge
                                                    variant="outline"
                                                    title="Previously waived — code changed"
                                                    className="text-[10px] border-amber-400 bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-600 w-fit whitespace-nowrap"
                                                >
                                                    Lapsed waiver
                                                </Badge>
                                            )}
                                        </div>
                                    </TableCell>
                                    <TableCell className="p-4 align-middle text-sm text-muted-foreground">
                                        {finding.scanners?.join(', ') || 'Unknown'}
                                    </TableCell>
                                </TableRow>
                            )
                        })}
                        {isFetchingNextPage && (
                            <TableRow>
                                <TableCell colSpan={6} className="p-4 text-center">
                                    <Loader2 className="h-6 w-6 animate-spin mx-auto text-muted-foreground" />
                                    <span className="sr-only">Loading more...</span>
                                </TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </table>
                </TooltipProvider>
            )}

            {/* Sentinel element — IntersectionObserver triggers load-more when this approaches the viewport */}
            <div ref={sentinelRef} className="h-1" />

            {selectedFinding && (
                <FindingDetailsModal
                    finding={selectedFinding}
                    projectId={projectId}
                    scanId={scanId}
                    scanContext={scanContext}
                    isOpen={!!selectedFinding}
                    onClose={closeSelectedFinding}
                    onSelectFinding={async (id) => {
                        // Prefer a match among the already-loaded rows.
                        let found = resolveRelatedFindingInRows(allRows, id)
                        // If not present locally (e.g. switching between
                        // quality/security tabs), fall back to the API.
                        if (!found) {
                            try {
                                found = await fetchRelatedFinding(scanId, id)
                            } catch (err) {
                                console.error('Failed to fetch finding details:', err)
                            }
                        }
                        if (found) setSelectedFinding(found);
                    }}
                />
            )}
        </div>
    )
}
