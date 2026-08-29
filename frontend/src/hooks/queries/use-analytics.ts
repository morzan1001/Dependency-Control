import { useQuery } from '@tanstack/react-query';
import { analyticsApi } from '@/api/analytics';
import type { ApiError } from '@/api/client';

export interface UpdateFrequencyOpts {
    windowDays?: number;
}

export const analyticsKeys = {
    all: ['analytics'] as const,
    dashboardStats: () => [...analyticsKeys.all, 'dashboard-stats'] as const,
    summary: () => [...analyticsKeys.all, 'summary'] as const,
    topDependencies: (limit: number, type?: string) => [...analyticsKeys.all, 'top-dependencies', { limit, type }] as const,
    dependencyTree: (projectId: string, scanId?: string) => [...analyticsKeys.all, 'dependency-tree', projectId, { scanId }] as const,
    impactAnalysis: (limit: number) => [...analyticsKeys.all, 'impact-analysis', { limit }] as const,
    search: (query: string, version?: string) => [...analyticsKeys.all, 'search', { query, version }] as const,
    componentFindings: (component: string, version?: string) => [...analyticsKeys.all, 'component-findings', { component, version }] as const,
    dependencyMetadata: (component: string, version?: string, type?: string) => [...analyticsKeys.all, 'dependency-metadata', { component, version, type }] as const,
    dependencyTypes: () => [...analyticsKeys.all, 'dependency-types'] as const,
    recommendations: (projectId: string, scanId?: string) => [...analyticsKeys.all, 'recommendations', projectId, { scanId }] as const,
    updateFrequency: (projectId: string, opts?: UpdateFrequencyOpts) => [...analyticsKeys.all, 'update-frequency', projectId, { ...opts }] as const,
    updateFrequencyComparison: (teamId?: string, opts?: UpdateFrequencyOpts) => [...analyticsKeys.all, 'update-frequency-comparison', { teamId, ...opts }] as const,
}

export const useDashboardStats = () => {
    return useQuery<Awaited<ReturnType<typeof analyticsApi.getDashboardStats>>, ApiError>({
        queryKey: analyticsKeys.dashboardStats(),
        queryFn: analyticsApi.getDashboardStats,
        staleTime: 2 * 60 * 1000, // stats are expensive to compute
        refetchOnWindowFocus: true,
        retry: 2,
    });
}

export const useSearchDependencies = (query: string, version?: string) => {
    return useQuery({
        queryKey: analyticsKeys.search(query, version),
        queryFn: () => analyticsApi.searchDependencies(query, version),
        enabled: !!query && query.length > 2
    })
}

export const useAnalyticsSummary = () => {
    return useQuery({
        queryKey: analyticsKeys.summary(),
        queryFn: analyticsApi.getSummary,
        staleTime: 5 * 60 * 1000,
        refetchOnWindowFocus: true,
    });
}

export const useTopDependencies = (limit: number = 20, type?: string) => {
    return useQuery({
        queryKey: analyticsKeys.topDependencies(limit, type),
        queryFn: () => analyticsApi.getTopDependencies(limit, type),
        staleTime: 5 * 60 * 1000,
        refetchOnWindowFocus: true,
    });
}

export const useDependencyTree = (projectId: string, scanId?: string) => {
    return useQuery({
        queryKey: analyticsKeys.dependencyTree(projectId, scanId),
        queryFn: () => analyticsApi.getDependencyTree(projectId, scanId),
        enabled: !!projectId,
        staleTime: 5 * 60 * 1000,
        refetchOnWindowFocus: true,
    });
}

export const useImpactAnalysis = (limit: number = 20) => {
    return useQuery({
        queryKey: analyticsKeys.impactAnalysis(limit),
        queryFn: () => analyticsApi.getImpactAnalysis(limit),
        staleTime: 5 * 60 * 1000,
        refetchOnWindowFocus: true,
    });
}

export const useComponentFindings = (component: string, version?: string) => {
    return useQuery({
        queryKey: analyticsKeys.componentFindings(component, version),
        queryFn: () => analyticsApi.getComponentFindings(component, version),
        enabled: !!component
    });
}

export const useDependencyMetadata = (component: string, version?: string, type?: string) => {
    return useQuery({
        queryKey: analyticsKeys.dependencyMetadata(component, version, type),
        queryFn: () => analyticsApi.getDependencyMetadata(component, version, type),
        enabled: !!component
    });
}

export const useDependencyTypes = () => {
    return useQuery({
        queryKey: analyticsKeys.dependencyTypes(),
        queryFn: analyticsApi.getDependencyTypes,
        staleTime: 30 * 60 * 1000, // types almost never change
        refetchOnWindowFocus: true,
    });
}

export const useProjectRecommendations = (projectId: string, scanId?: string) => {
    return useQuery({
        queryKey: analyticsKeys.recommendations(projectId, scanId),
        queryFn: () => analyticsApi.getProjectRecommendations(projectId, scanId),
        enabled: !!projectId,
        staleTime: 5 * 60 * 1000,
        refetchOnWindowFocus: true,
    });
}

// An uncached update-frequency run is open-ended, so neither query ever refetches on its own;
// new results only appear once the user asks again.
export const useUpdateFrequency = (projectId: string, opts?: UpdateFrequencyOpts) => {
    return useQuery<Awaited<ReturnType<typeof analyticsApi.getUpdateFrequency>>, ApiError>({
        queryKey: analyticsKeys.updateFrequency(projectId, opts),
        queryFn: ({ signal }) => analyticsApi.getUpdateFrequency(projectId, opts, signal),
        enabled: !!projectId,
        staleTime: 5 * 60 * 1000,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
        retry: false,
    });
}

export const useUpdateFrequencyComparison = (
    teamId: string | undefined,
    opts: UpdateFrequencyOpts | undefined,
    enabled: boolean,
) => {
    return useQuery<Awaited<ReturnType<typeof analyticsApi.getUpdateFrequencyComparison>>, ApiError>({
        queryKey: analyticsKeys.updateFrequencyComparison(teamId, opts),
        queryFn: ({ signal }) => analyticsApi.getUpdateFrequencyComparison(teamId, opts, signal),
        enabled,
        staleTime: 5 * 60 * 1000,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
        retry: false,
    });
}
