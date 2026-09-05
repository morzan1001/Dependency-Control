import { api } from '@/api/client';
import { SMALL_PAGE_SIZE } from '@/lib/constants';
import { ProjectBranchTips, Scan, ScanAnalysisResult, SbomResponse, ScanFindingsParams, ScanFindingsResponse, ScanStats, ScanWithReleases } from '@/types/scan';

export const scanApi = {
    getRecent: async (): Promise<Scan[]> => {
        const response = await api.get<Scan[]>('/projects/scans', { params: { limit: 5, sort_by: 'created_at', sort_order: 'desc' } });
        return response.data;
    },

    getProjectScans: async (id: string, params: {
        skip?: number; limit?: number; branch?: string; sortBy?: string;
        sortOrder?: 'asc' | 'desc'; excludeRescans?: boolean; excludeDeletedBranches?: boolean;
        isRelease?: boolean;
    } = {}): Promise<ScanWithReleases[]> => {
        // isRelease is tri-state: undefined is no filter, false selects the scans that are not releases.
        const { skip = 0, limit = SMALL_PAGE_SIZE, branch, sortBy = 'created_at', sortOrder = 'desc', excludeRescans = false, excludeDeletedBranches = false, isRelease } = params;
        const response = await api.get<ScanWithReleases[]>(`/projects/${id}/scans`, {
          params: { skip, limit, branch, sort_by: sortBy, sort_order: sortOrder, exclude_rescans: excludeRescans, exclude_deleted_branches: excludeDeletedBranches, is_release: isRelease }
        });
        return response.data;
    },

    getBranchTips: async (id: string): Promise<ProjectBranchTips> => {
        const response = await api.get<ProjectBranchTips>(`/projects/${id}/scans/branch-tips`);
        return response.data;
    },

    getHistory: async (projectId: string, scanId: string): Promise<Scan[]> => {
        const response = await api.get<Scan[]>(`/projects/${projectId}/scans/${scanId}/history`);
        return response.data;
    },

    triggerRescan: async (projectId: string, scanId: string): Promise<Scan> => {
        const response = await api.post<Scan>(`/projects/${projectId}/scans/${scanId}/rescan`);
        return response.data;
    },

    getOne: async (scanId: string): Promise<ScanWithReleases> => {
        const response = await api.get<ScanWithReleases>(`/projects/scans/${scanId}`);
        return response.data;
    },

    getResults: async (scanId: string): Promise<ScanAnalysisResult[]> => {
        const response = await api.get<ScanAnalysisResult[]>(`/projects/scans/${scanId}/results`);
        return response.data;
    },

    getSboms: async (scanId: string): Promise<SbomResponse[]> => {
        const response = await api.get<SbomResponse[]>(`/projects/scans/${scanId}/sboms`);
        return response.data;
    },

    getFindings: async (scanId: string, params: ScanFindingsParams = {}): Promise<ScanFindingsResponse> => {
        const response = await api.get<ScanFindingsResponse>(`/projects/scans/${scanId}/findings`, { params });
        return response.data;
    },

    getStats: async (scanId: string): Promise<ScanStats> => {
        const response = await api.get<ScanStats>(`/projects/scans/${scanId}/stats`);
        return response.data;
    }
}
