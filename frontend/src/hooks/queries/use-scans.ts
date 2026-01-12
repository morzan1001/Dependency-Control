import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { scanApi, ScanFindingsParams } from '@/api/scans';

export const scanKeys = {
    all: ['scans'] as const,
    recent: () => [...scanKeys.all, 'recent'] as const,
    project: (projectId: string) => [...scanKeys.all, 'project', projectId] as const,
    list: (projectId: string, filters: unknown) => [...scanKeys.project(projectId), 'list', filters] as const,
    details: () => [...scanKeys.all, 'detail'] as const,
    detail: (scanId: string) => [...scanKeys.details(), scanId] as const,
    history: (projectId: string, scanId: string) => [...scanKeys.project(projectId), 'history', scanId] as const,
    findings: (scanId: string, filters: unknown) => [...scanKeys.detail(scanId), 'findings', filters] as const,
    results: (scanId: string) => [...scanKeys.detail(scanId), 'results'] as const,
    stats: (scanId: string) => [...scanKeys.detail(scanId), 'stats'] as const,
    sboms: (scanId: string) => [...scanKeys.detail(scanId), 'sboms'] as const,
}

export const useRecentScans = () => {
    return useQuery({
        queryKey: scanKeys.recent(),
        queryFn: scanApi.getRecent,
        staleTime: 60 * 1000 // 1 minute
    });
}

export const useProjectScans = (
    projectId: string, 
    page: number = 1, 
    limit: number = 20, 
    branch?: string, 
    sortBy: string = 'created_at', 
    sortOrder: 'asc' | 'desc' = 'desc',
    excludeRescans: boolean = false
) => {
    return useQuery({
        queryKey: scanKeys.list(projectId, { page, limit, branch, sortBy, sortOrder, excludeRescans }),
        queryFn: () => scanApi.getProjectScans(projectId, (page - 1) * limit, limit, branch, sortBy, sortOrder, excludeRescans),
        enabled: !!projectId,
        placeholderData: keepPreviousData
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
             // Invalidate list of scans for the project
             queryClient.invalidateQueries({ queryKey: scanKeys.project(variables.projectId) });
             // Optionally invalidate scan detail if it redirects to new scan
        }
    })
}
