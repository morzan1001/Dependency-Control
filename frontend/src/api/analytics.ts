import { api } from '@/api/client';
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
    RecommendationsResponse
} from '@/types/analytics';

export const analyticsApi = {
    getDashboardStats: async () => {
        const response = await api.get<DashboardStats>('/projects/dashboard/stats');
        return response.data;
    },

    searchDependencies: async (query: string, version?: string) => {
        const params = new URLSearchParams();
        params.append('q', query);
        if (version) params.append('version', version);
        
        const response = await api.get<SearchResult[]>('/analytics/search', { params });
        return response.data;
    },

    getSummary: async () => {
        const response = await api.get<AnalyticsSummary>('/analytics/summary');
        return response.data;
    },
      
    getTopDependencies: async (limit = 20, type?: string) => {
        const params = new URLSearchParams();
        params.append('limit', limit.toString());
        if (type) params.append('type', type);
        const response = await api.get<DependencyUsage[]>('/analytics/dependencies/top', { params });
        return response.data;
    },
      
    getDependencyTree: async (projectId: string, scanId?: string) => {
        const params = new URLSearchParams();
        if (scanId) params.append('scan_id', scanId);
        const response = await api.get<DependencyTreeNode[]>(`/analytics/projects/${projectId}/dependency-tree`, { params });
        return response.data;
    },
      
    getImpactAnalysis: async (limit = 20) => {
        const params = new URLSearchParams();
        params.append('limit', limit.toString());
        const response = await api.get<ImpactAnalysisResult[]>('/analytics/impact', { params });
        return response.data;
    },
      
    getVulnerabilityHotspots: async (params: HotspotsQueryParams = {}) => {
        const urlParams = new URLSearchParams();
        if (params.skip !== undefined) urlParams.append('skip', params.skip.toString());
        urlParams.append('limit', (params.limit ?? 20).toString());
        if (params.sort_by) urlParams.append('sort_by', params.sort_by);
        if (params.sort_order) urlParams.append('sort_order', params.sort_order);
        const response = await api.get<VulnerabilityHotspot[]>('/analytics/hotspots', { params: urlParams });
        return response.data;
    },
      
    searchDependenciesAdvanced: async (
        query: string, 
        options?: AdvancedSearchOptions
    ): Promise<AdvancedSearchResponse> => {
        const params = new URLSearchParams();
        params.append('q', query);
        if (options?.version) params.append('version', options.version);
        if (options?.type) params.append('type', options.type);
        if (options?.source_type) params.append('source_type', options.source_type);
        if (options?.has_vulnerabilities !== undefined) {
          params.append('has_vulnerabilities', options.has_vulnerabilities.toString());
        }
        if (options?.project_ids?.length) {
          params.append('project_ids', options.project_ids.join(','));
        }
        if (options?.sort_by) params.append('sort_by', options.sort_by);
        if (options?.sort_order) params.append('sort_order', options.sort_order);
        if (options?.skip !== undefined) params.append('skip', options.skip.toString());
        if (options?.limit) params.append('limit', options.limit.toString());
        const response = await api.get<AdvancedSearchResponse>('/analytics/search', { params });
        return response.data;
    },
    
    searchVulnerabilities: async (
        query: string,
        options?: VulnerabilitySearchOptions
      ): Promise<VulnerabilitySearchResponse> => {
        const params = new URLSearchParams();
        params.append('q', query);
        if (options?.severity) params.append('severity', options.severity);
        if (options?.in_kev !== undefined) params.append('in_kev', options.in_kev.toString());
        if (options?.has_fix !== undefined) params.append('has_fix', options.has_fix.toString());
        if (options?.finding_type) params.append('finding_type', options.finding_type);
        if (options?.project_ids?.length) {
          params.append('project_ids', options.project_ids.join(','));
        }
        if (options?.include_waived !== undefined) {
          params.append('include_waived', options.include_waived.toString());
        }
        if (options?.sort_by) params.append('sort_by', options.sort_by);
        if (options?.sort_order) params.append('sort_order', options.sort_order);
        if (options?.skip !== undefined) params.append('skip', options.skip.toString());
        if (options?.limit) params.append('limit', options.limit.toString());
        const response = await api.get<VulnerabilitySearchResponse>('/analytics/vulnerability-search', { params });
        return response.data;
    },

    getComponentFindings: async (component: string, version?: string) => {
        const params = new URLSearchParams();
        params.append('component', component);
        if (version) params.append('version', version);
        const response = await api.get<ComponentFinding[]>('/analytics/component-findings', { params });
        return response.data;
    },

    getDependencyMetadata: async (
        component: string, 
        version?: string, 
        type?: string
      ): Promise<DependencyMetadata | null> => {
        const params = new URLSearchParams();
        params.append('component', component);
        if (version) params.append('version', version);
        if (type) params.append('type', type);
        const response = await api.get<DependencyMetadata | null>('/analytics/dependency-metadata', { params });
        return response.data;
    },
      
    getDependencyTypes: async () => {
        const response = await api.get<string[]>('/analytics/dependency-types');
        return response.data;
    },
    
    getProjectRecommendations: async (projectId: string, scanId?: string) => {
        const params = new URLSearchParams();
        if (scanId) params.append('scan_id', scanId);
        const response = await api.get<RecommendationsResponse>(
            `/analytics/projects/${projectId}/recommendations`,
            { params }
        );
        return response.data;
    }
}
