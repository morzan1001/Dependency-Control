import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { scanApi } from '@/api/scans';
import { SMALL_PAGE_SIZE } from '@/lib/constants';
import { ScanFindingsParams, ScanWithReleases } from '@/types/scan';

export interface ScanListFilters {
    page: number;
    limit: number;
    branch?: string;
    sortBy: string;
    sortOrder: 'asc' | 'desc';
    excludeRescans: boolean;
    excludeDeletedBranches: boolean;
    // Tri-state, and part of the query key: leaving it out means "every scan", false means
    // "not a release" — which on the backend includes scans predating the flag.
    isRelease?: boolean;
}

export const scanKeys = {
    all: ['scans'] as const,
    recent: () => [...scanKeys.all, 'recent'] as const,
    project: (projectId: string) => [...scanKeys.all, 'project', projectId] as const,
    list: (projectId: string, filters: ScanListFilters) => [...scanKeys.project(projectId), 'list', filters] as const,
    details: () => [...scanKeys.all, 'detail'] as const,
    detail: (scanId: string) => [...scanKeys.details(), scanId] as const,
    branchTips: (projectId: string) => [...scanKeys.project(projectId), 'branch-tips'] as const,
    history: (projectId: string, scanId: string) => [...scanKeys.project(projectId), 'history', scanId] as const,
    findings: (scanId: string, filters: ScanFindingsParams) => [...scanKeys.detail(scanId), 'findings', filters] as const,
    results: (scanId: string) => [...scanKeys.detail(scanId), 'results'] as const,
    stats: (scanId: string) => [...scanKeys.detail(scanId), 'stats'] as const,
    sboms: (scanId: string) => [...scanKeys.detail(scanId), 'sboms'] as const,
    window: (projectId: string, pages: number) => [...scanKeys.project(projectId), 'window', pages] as const,
}

export const useRecentScans = () => {
    return useQuery({
        queryKey: scanKeys.recent(),
        queryFn: scanApi.getRecent,
        staleTime: 60 * 1000
    });
}

export const useProjectScans = (
    projectId: string,
    filters: Partial<ScanListFilters> = {}
) => {
    const { page = 1, limit = SMALL_PAGE_SIZE, branch, sortBy = 'created_at', sortOrder = 'desc', excludeRescans = false, excludeDeletedBranches = false, isRelease } = filters;
    const resolvedFilters: ScanListFilters = { page, limit, branch, sortBy, sortOrder, excludeRescans, excludeDeletedBranches, isRelease };
    return useQuery({
        queryKey: scanKeys.list(projectId, resolvedFilters),
        queryFn: () => scanApi.getProjectScans(projectId, {
            skip: (page - 1) * limit, limit, branch, sortBy, sortOrder, excludeRescans, excludeDeletedBranches, isRelease
        }),
        enabled: !!projectId,
        placeholderData: keepPreviousData
    });
}

/** Scans a picker offers per page; a picker asks for another page rather than stopping silently. */
export const SCAN_WINDOW_PAGE_SIZE = 50

export interface ScanWindow {
    scans: ScanWithReleases[]
    /** The window reached the project's oldest scan, so nothing older exists to offer. */
    complete: boolean
}

// A picker cannot say "no older scan" from one page, so the window reports whether it read to the end.
export const useProjectScanWindow = (projectId: string, pages: number) => {
    return useQuery<ScanWindow>({
        queryKey: scanKeys.window(projectId, pages),
        queryFn: async () => {
            const scans: ScanWithReleases[] = []
            for (let page = 0; page < pages; page++) {
                const batch = await scanApi.getProjectScans(projectId, {
                    skip: page * SCAN_WINDOW_PAGE_SIZE, limit: SCAN_WINDOW_PAGE_SIZE, excludeRescans: true,
                })
                scans.push(...batch)
                if (batch.length < SCAN_WINDOW_PAGE_SIZE) return { scans, complete: true }
            }
            return { scans, complete: false }
        },
        enabled: !!projectId,
        placeholderData: keepPreviousData,
    });
}

// Every branch of the project, so a branch verdict never depends on how many scans fit on a page.
export const useProjectBranchTips = (projectId: string) => {
    return useQuery({
        queryKey: scanKeys.branchTips(projectId),
        queryFn: () => scanApi.getBranchTips(projectId),
        enabled: !!projectId
    });
}

export const useScan = (scanId: string) => {
    return useQuery({
        queryKey: scanKeys.detail(scanId),
        queryFn: () => scanApi.getOne(scanId),
        enabled: !!scanId
    })
}

export const useScanHistory = (projectId: string, scanId: string) => {
    return useQuery({
        queryKey: scanKeys.history(projectId, scanId),
        queryFn: () => scanApi.getHistory(projectId, scanId),
        enabled: !!projectId && !!scanId
    })
}

export const useScanFindings = (scanId: string, params: ScanFindingsParams) => {
    return useQuery({
        queryKey: scanKeys.findings(scanId, params),
        queryFn: () => scanApi.getFindings(scanId, params),
        enabled: !!scanId,
        placeholderData: keepPreviousData
    })
}

export const useScanResults = (scanId: string) => {
    return useQuery({
        queryKey: scanKeys.results(scanId),
        queryFn: () => scanApi.getResults(scanId),
        enabled: !!scanId
    })
}

export const useScanStats = (scanId: string) => {
    return useQuery({
        queryKey: scanKeys.stats(scanId),
        queryFn: () => scanApi.getStats(scanId),
        enabled: !!scanId
    })
}

export const useScanSboms = (scanId: string) => {
    return useQuery({
        queryKey: scanKeys.sboms(scanId),
        queryFn: () => scanApi.getSboms(scanId),
        enabled: !!scanId
    })
}

export const useTriggerRescan = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ projectId, scanId }: { projectId: string, scanId: string }) => scanApi.triggerRescan(projectId, scanId),
        onSuccess: (_, variables) => {
             queryClient.invalidateQueries({ queryKey: scanKeys.project(variables.projectId) });
        }
    })
}
