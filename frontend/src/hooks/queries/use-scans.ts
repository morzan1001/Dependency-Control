import { useEffect, useRef } from 'react';
import { useInfiniteQuery, useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { projectApi } from '@/api/projects';
import { scanApi } from '@/api/scans';
import { SMALL_PAGE_SIZE } from '@/lib/constants';
import { isScanInProgress } from '@/lib/scan-status';
import { Scan } from '@/types/scan';

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
    results: (scanId: string) => [...scanKeys.detail(scanId), 'results'] as const,
    result: (scanId: string, resultId: string) => [...scanKeys.results(scanId), resultId] as const,
    stats: (scanId: string) => [...scanKeys.detail(scanId), 'stats'] as const,
    sboms: (scanId: string) => [...scanKeys.detail(scanId), 'sboms'] as const,
    sbom: (scanId: string, index: number) => [...scanKeys.sboms(scanId), index] as const,
    window: (projectId: string) => [...scanKeys.project(projectId), 'window'] as const,
}

const SCAN_POLL_INTERVAL_MS = 5000

const pollWhileAnalysing = (scans?: Scan[]) =>
    scans?.some((s) => isScanInProgress(s.status) || isScanInProgress(s.latest_run?.status)) ? SCAN_POLL_INTERVAL_MS : false

export const useRecentScans = () => {
    return useQuery({
        queryKey: scanKeys.recent(),
        queryFn: scanApi.getRecent,
        staleTime: 60 * 1000,
        refetchInterval: (q) => pollWhileAnalysing(q.state.data),
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
        placeholderData: keepPreviousData,
        refetchInterval: (q) => pollWhileAnalysing(q.state.data),
    });
}

/** Scans a picker offers per page; a picker asks for another page rather than stopping silently. */
export const SCAN_WINDOW_PAGE_SIZE = 50

export const useProjectScanWindow = (projectId: string) => {
    return useInfiniteQuery({
        queryKey: scanKeys.window(projectId),
        queryFn: ({ pageParam }) => scanApi.getProjectScans(projectId, {
            skip: pageParam, limit: SCAN_WINDOW_PAGE_SIZE, excludeRescans: true,
        }),
        initialPageParam: 0,
        getNextPageParam: (lastPage, pages) =>
            lastPage.length < SCAN_WINDOW_PAGE_SIZE ? undefined : pages.length * SCAN_WINDOW_PAGE_SIZE,
        enabled: !!projectId,
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
    const queryClient = useQueryClient();
    const query = useQuery({
        queryKey: scanKeys.detail(scanId),
        queryFn: () => scanApi.getOne(scanId),
        enabled: !!scanId,
        refetchInterval: (q) => (isScanInProgress(q.state.data?.status) ? SCAN_POLL_INTERVAL_MS : false),
    })
    const inProgress = isScanInProgress(query.data?.status);
    const wasInProgress = useRef(inProgress);
    useEffect(() => {
        if (wasInProgress.current && !inProgress) {
            queryClient.invalidateQueries({ predicate: (q) => q.queryKey.includes(scanId) });
        }
        wasInProgress.current = inProgress;
    }, [inProgress, queryClient, scanId]);
    return query;
}

export const useScanHistory = (projectId: string, scanId: string) => {
    return useQuery({
        queryKey: scanKeys.history(projectId, scanId),
        queryFn: () => scanApi.getHistory(projectId, scanId),
        enabled: !!projectId && !!scanId
    })
}

export const useScanResults = (scanId: string, enabled = true) => {
    return useQuery({
        queryKey: scanKeys.results(scanId),
        queryFn: () => scanApi.getResults(scanId),
        enabled: !!scanId && enabled
    })
}

export const useScanResult = (scanId: string, resultId: string) => {
    return useQuery({
        queryKey: scanKeys.result(scanId, resultId),
        queryFn: () => scanApi.getResult(scanId, resultId)
    })
}

export const useScanStats = (scanId: string) => {
    return useQuery({
        queryKey: scanKeys.stats(scanId),
        queryFn: () => scanApi.getStats(scanId),
        enabled: !!scanId
    })
}

export const useScanSboms = (scanId: string, enabled: boolean) => {
    return useQuery({
        queryKey: scanKeys.sboms(scanId),
        queryFn: () => scanApi.getSboms(scanId),
        enabled: !!scanId && enabled
    })
}

export const useScanSbom = (scanId: string, index: number) => {
    return useQuery({
        queryKey: scanKeys.sbom(scanId, index),
        queryFn: () => scanApi.getSbom(scanId, index)
    })
}

export const useUnpinScan = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ projectId, scanId }: { projectId: string, scanId: string }) => projectApi.unpinScan(projectId, scanId),
        onSuccess: (_, variables) => queryClient.invalidateQueries({ queryKey: scanKeys.detail(variables.scanId) }),
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
