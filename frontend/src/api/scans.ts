import { api } from '@/api/client';
import { Scan, Finding, ScanAnalysisResult } from '@/types/scan';

// Sbom Types (Moved from lib/api.ts)
export interface SbomToolComponent {
  name: string;
}

export interface SbomTool {
  name?: string;
  vendor?: string;
}

export interface SbomMetadata {
  component?: {
    name?: string;
  };
  tools?: SbomTool[] | {
    components?: SbomToolComponent[];
  };
}

export interface SbomData {
  metadata?: SbomMetadata;
  serialNumber?: string;
  [key: string]: unknown;
}

export interface SbomResponse {
  index: number;
  filename: string | null;
  storage: 'gridfs' | 'inline';
  sbom: SbomData | null;
  error?: string;
}

export interface ScanFindingsParams {
  skip?: number;
  limit?: number;
  sort_by?: string;
  sort_order?: string;
  type?: string;
  category?: string;
  severity?: string;
  search?: string;
}

export interface ScanFindingsResponse {
  items: Finding[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export const scanApi = {
    getRecent: async () => {
        const response = await api.get<Scan[]>('/projects/scans', { params: { limit: 5, sort_by: 'created_at', sort_order: 'desc' } });
        return response.data;
    },

    getProjectScans: async (id: string, skip: number = 0, limit: number = 20, branch?: string, sortBy: string = 'created_at', sortOrder: 'asc' | 'desc' = 'desc', excludeRescans: boolean = false) => {
        const response = await api.get<Scan[]>(`/projects/${id}/scans`, {
          params: { skip, limit, branch, sort_by: sortBy, sort_order: sortOrder, exclude_rescans: excludeRescans }
        });
        return response.data;
    },
      
    getHistory: async (projectId: string, scanId: string) => {
        const response = await api.get<Scan[]>(`/projects/${projectId}/scans/${scanId}/history`);
        return response.data;
    },
      
    triggerRescan: async (projectId: string, scanId: string) => {
        const response = await api.post<Scan>(`/projects/${projectId}/scans/${scanId}/rescan`);
        return response.data;
    },

    getOne: async (scanId: string) => {
        const response = await api.get<Scan>(`/projects/scans/${scanId}`);
        return response.data;
    },

    getResults: async (scanId: string) => {
        // Note: AnalysisResult type might be needed if strictly typed, but sticking to general or importing if available
        const response = await api.get<ScanAnalysisResult[]>(`/projects/scans/${scanId}/results`);
        return response.data;
    },

    getSboms: async (scanId: string): Promise<SbomResponse[]> => {
        const response = await api.get<SbomResponse[]>(`/projects/scans/${scanId}/sboms`);
        return response.data;
    },

    getFindings: async (scanId: string, params: ScanFindingsParams = {}) => {
        const response = await api.get<ScanFindingsResponse>(`/projects/scans/${scanId}/findings`, { params });
        return response.data;
    },
      
    getStats: async (scanId: string) => {
        const response = await api.get<Record<string, number>>(`/projects/scans/${scanId}/stats`);
        return response.data;
    }
}
