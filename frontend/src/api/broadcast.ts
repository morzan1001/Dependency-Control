import { api } from '@/api/client';
import { BroadcastRequest, BroadcastResult, BroadcastHistoryItem, PackageSuggestions } from '@/types/broadcast';

export const broadcastApi = {
  send: async (data: BroadcastRequest): Promise<BroadcastResult> => {
    const response = await api.post<BroadcastResult>('/notifications/broadcast', data);
    return response.data;
  },
  getHistory: async (): Promise<BroadcastHistoryItem[]> => {
    const response = await api.get<BroadcastHistoryItem[]>('/notifications/history');
    return response.data;
  },
  suggestPackages: async (q: string): Promise<PackageSuggestions> => {
    const response = await api.get<PackageSuggestions>('/notifications/packages/suggest', { params: { q } });
    return response.data;
  }
};
