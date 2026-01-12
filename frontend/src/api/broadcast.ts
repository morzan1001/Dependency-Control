import { apiClient } from './client';
import { BroadcastRequest, BroadcastResult, BroadcastHistoryItem } from '@/types/broadcast';

export const broadcastApi = {
  send: async (data: BroadcastRequest): Promise<BroadcastResult> => {
    const response = await apiClient.post<BroadcastResult>('/notifications/broadcast', data);
    return response.data;
  },
  getHistory: async (): Promise<BroadcastHistoryItem[]> => {
    const response = await apiClient.get<BroadcastHistoryItem[]>('/notifications/history');
    return response.data;
  }
};
