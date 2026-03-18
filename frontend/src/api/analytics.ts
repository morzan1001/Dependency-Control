import { api, buildQueryParams } from '@/api/client';
import {
    DashboardStats,
    SearchResult,
    AnalyticsSummary,
    DependencyUsage,
    DependencyTreeNode,
    ImpactAnalysisResult,
    VulnerabilityHotspot,
    HotspotsQueryParams,
    AdvancedSearchResponse,
    AdvancedSearchOptions,
    VulnerabilitySearchResponse,
    VulnerabilitySearchOptions,
    ComponentFinding,
    DependencyMetadata,
    RecommendationsResponse,
    UpdateFrequencyMetrics,
    UpdateFrequencyComparison,
} from '@/types/analytics';

export const analyticsApi = {
    getDashboardStats: async (): Promise<DashboardStats> => {
        const response = await api.get<DashboardStats>('/projects/dashboard/stats');
        return response.data;
    },

    searchDependencies: async (query: string, version?: string): Promise<SearchResult[]> => {
        const params = buildQueryParams({ q: query, version });
        const response = await api.get<SearchResult[]>('/analytics/search', { params });
        return response.data;
    },

    getSummary: async (): Promise<AnalyticsSummary> => {
        const response = await api.get<AnalyticsSummary>('/analytics/summary');
        return response.data;
    },

    getTopDependencies: async (limit = 20, type?: string): Promise<DependencyUsage[]> => {
        const params = buildQueryParams({ limit, type });
        const response = await api.get<DependencyUsage[]>('/analytics/dependencies/top', { params });
        return response.data;
    },

    getDependencyTree: async (projectId: string, scanId?: string): Promise<DependencyTreeNode[]> => {
        const params = buildQueryParams({ scan_id: scanId });
        const response = await api.get<DependencyTreeNode[]>(`/analytics/projects/${projectId}/dependency-tree`, { params });
        return response.data;
    },

    getImpactAnalysis: async (limit = 20): Promise<ImpactAnalysisResult[]> => {
        const params = buildQueryParams({ limit });
        const response = await api.get<ImpactAnalysisResult[]>('/analytics/impact', { params });
        return response.data;
    },

    getVulnerabilityHotspots: async (options: HotspotsQueryParams = {}): Promise<VulnerabilityHotspot[]> => {
        const params = buildQueryParams({
            skip: options.skip,
            limit: options.limit ?? 20,
            sort_by: options.sort_by,
            sort_order: options.sort_order,
        });
        const response = await api.get<VulnerabilityHotspot[]>('/analytics/hotspots', { params });
        return response.data;
    },

    searchDependenciesAdvanced: async (
        query: string,
        options?: AdvancedSearchOptions
    ): Promise<AdvancedSearchResponse> => {
        const params = buildQueryParams({
            q: query,
            version: options?.version,
            type: options?.type,
            source_type: options?.source_type,
            has_vulnerabilities: options?.has_vulnerabilities,
            project_ids: options?.project_ids,
            sort_by: options?.sort_by,
            sort_order: options?.sort_order,
            skip: options?.skip,
            limit: options?.limit,
        });
        const response = await api.get<AdvancedSearchResponse>('/analytics/search', { params });
        return response.data;
    },

    searchVulnerabilities: async (
        query: string,
        options?: VulnerabilitySearchOptions
      ): Promise<VulnerabilitySearchResponse> => {
        const params = buildQueryParams({
            q: query,
            severity: options?.severity,
            in_kev: options?.in_kev,
            has_fix: options?.has_fix,
            finding_type: options?.finding_type,
            project_ids: options?.project_ids,
            include_waived: options?.include_waived,
            sort_by: options?.sort_by,
            sort_order: options?.sort_order,
            skip: options?.skip,
            limit: options?.limit,
        });
        const response = await api.get<VulnerabilitySearchResponse>('/analytics/vulnerability-search', { params });
        return response.data;
    },

    getComponentFindings: async (component: string, version?: string): Promise<ComponentFinding[]> => {
        const params = buildQueryParams({ component, version });
        const response = await api.get<ComponentFinding[]>('/analytics/component-findings', { params });
        return response.data;
    },

    getDependencyMetadata: async (
        component: string,
        version?: string,
        type?: string
      ): Promise<DependencyMetadata | null> => {
        const params = buildQueryParams({ component, version, type });
        const response = await api.get<DependencyMetadata | null>('/analytics/dependency-metadata', { params });
        return response.data;
    },

    getDependencyTypes: async (): Promise<string[]> => {
        const response = await api.get<string[]>('/analytics/dependency-types');
        return response.data;
    },

    getProjectRecommendations: async (projectId: string, scanId?: string): Promise<RecommendationsResponse> => {
        const params = buildQueryParams({ scan_id: scanId });
        const response = await api.get<RecommendationsResponse>(
            `/analytics/projects/${projectId}/recommendations`,
            { params }
        );
        return response.data;
    },

    getUpdateFrequency: async (projectId: string, maxScans?: number): Promise<UpdateFrequencyMetrics> => {
        const params = buildQueryParams({ max_scans: maxScans });
        const response = await api.get<UpdateFrequencyMetrics>(
            `/analytics/projects/${projectId}/update-frequency`,
            { params }
        );
        return response.data;
    },

    getUpdateFrequencyComparison: async (teamId?: string, maxScans?: number): Promise<UpdateFrequencyComparison> => {
        const params = buildQueryParams({ team_id: teamId, max_scans: maxScans });
        const response = await api.get<UpdateFrequencyComparison>(
            '/analytics/update-frequency/comparison',
            { params }
        );
        return response.data;
    },
}
