import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { analyticsApi } from '@/api/analytics';
import { HotspotsQueryParams, VulnerabilitySearchOptions, AdvancedSearchOptions } from '@/types/analytics';
import type { ApiError } from '@/api/client';

export const analyticsKeys = {
    all: ['analytics'] as const,
    dashboardStats: () => [...analyticsKeys.all, 'dashboard-stats'] as const,
    summary: () => [...analyticsKeys.all, 'summary'] as const,
    topDependencies: (limit: number, type?: string) => [...analyticsKeys.all, 'top-dependencies', { limit, type }] as const,
    dependencyTree: (projectId: string, scanId?: string) => [...analyticsKeys.all, 'dependency-tree', projectId, { scanId }] as const,
    impactAnalysis: (limit: number) => [...analyticsKeys.all, 'impact-analysis', { limit }] as const,
    hotspots: (params: HotspotsQueryParams) => [...analyticsKeys.all, 'hotspots', params] as const,
    search: (query: string, version?: string) => [...analyticsKeys.all, 'search', { query, version }] as const,
    advancedSearch: (query: string, options?: AdvancedSearchOptions) => [...analyticsKeys.all, 'search-advanced', { query, options }] as const,
    vulnerabilitySearch: (query: string, options?: VulnerabilitySearchOptions) => [...analyticsKeys.all, 'search-vulnerabilities', { query, options }] as const,
    componentFindings: (component: string, version?: string) => [...analyticsKeys.all, 'component-findings', { component, version }] as const,
    dependencyMetadata: (component: string, version?: string, type?: string) => [...analyticsKeys.all, 'dependency-metadata', { component, version, type }] as const,
    dependencyTypes: () => [...analyticsKeys.all, 'dependency-types'] as const,
    recommendations: (projectId: string, scanId?: string) => [...analyticsKeys.all, 'recommendations', projectId, { scanId }] as const,
}

export const useDashboardStats = () => {
    return useQuery<Awaited<ReturnType<typeof analyticsApi.getDashboardStats>>, ApiError>({
        queryKey: analyticsKeys.dashboardStats(),
        queryFn: analyticsApi.getDashboardStats,
        staleTime: 2 * 60 * 1000, // 2 minutes - stats are expensive to compute
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
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
}

export const useTopDependencies = (limit: number = 20, type?: string) => {
    return useQuery({
        queryKey: analyticsKeys.topDependencies(limit, type),
        queryFn: () => analyticsApi.getTopDependencies(limit, type),
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
}

export const useDependencyTree = (projectId: string, scanId?: string) => {
    return useQuery({
        queryKey: analyticsKeys.dependencyTree(projectId, scanId),
        queryFn: () => analyticsApi.getDependencyTree(projectId, scanId),
        enabled: !!projectId,
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
}

export const useImpactAnalysis = (limit: number = 20) => {
    return useQuery({
        queryKey: analyticsKeys.impactAnalysis(limit),
        queryFn: () => analyticsApi.getImpactAnalysis(limit),
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
}

export const useVulnerabilityHotspots = (params: HotspotsQueryParams) => {
    return useQuery({
        queryKey: analyticsKeys.hotspots(params),
        queryFn: () => analyticsApi.getVulnerabilityHotspots(params),
        placeholderData: keepPreviousData
    });
}

export const useAdvancedSearch = (query: string, options?: AdvancedSearchOptions) => {
    return useQuery({
        queryKey: analyticsKeys.advancedSearch(query, options),
        queryFn: () => analyticsApi.searchDependenciesAdvanced(query, options),
        enabled: !!query,
        placeholderData: keepPreviousData
    });
}

export const useVulnerabilitySearch = (query: string, options?: VulnerabilitySearchOptions) => {
    return useQuery({
        queryKey: analyticsKeys.vulnerabilitySearch(query, options),
        queryFn: () => analyticsApi.searchVulnerabilities(query, options),
        enabled: !!query,
        placeholderData: keepPreviousData
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
        staleTime: 30 * 60 * 1000, // 30 minutes - types almost never change
    });
}

export const useProjectRecommendations = (projectId: string, scanId?: string) => {
    return useQuery({
        queryKey: analyticsKeys.recommendations(projectId, scanId),
        queryFn: () => analyticsApi.getProjectRecommendations(projectId, scanId),
        enabled: !!projectId,
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
}
