import { useMutation, useInfiniteQuery, useQuery, useQueryClient, keepPreviousData, type QueryClient } from '@tanstack/react-query';
import { waiverApi } from '@/api/waivers';
import { WaiverUpdate } from '@/types/waiver';
import { DEFAULT_PAGE_SIZE } from '@/lib/constants';
import { scanKeys } from './use-scans';
import { analyticsKeys } from './use-analytics';
import { projectKeys } from './use-projects';

export const waiverKeys = {
    all: ['waivers'] as const,
    project: (projectId: string) => [...waiverKeys.all, 'project', projectId] as const,
    projectWithParams: (projectId: string, search?: string, sortBy?: string, sortOrder?: string, orphaned?: boolean, active?: boolean) =>
        [...waiverKeys.project(projectId), { search, sortBy, sortOrder, orphaned, active }] as const,
    global: ['waivers', 'global'] as const,
    globalWithParams: (search?: string, sortBy?: string, sortOrder?: string, orphaned?: boolean) =>
        ['waivers', 'global', { search, sortBy, sortOrder, orphaned }] as const,
};

const invalidateWaiverDependents = (queryClient: QueryClient) => {
    queryClient.invalidateQueries({ queryKey: scanKeys.all });
    queryClient.invalidateQueries({ queryKey: ['findings'] });
    queryClient.invalidateQueries({ queryKey: ['waived-findings-probe'] });
    queryClient.invalidateQueries({ queryKey: analyticsKeys.all });
    queryClient.invalidateQueries({ queryKey: projectKeys.all });
};

export const useCreateWaiver = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: waiverApi.create,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: waiverKeys.all });
            invalidateWaiverDependents(queryClient);
        }
    })
}

export const useUpdateWaiver = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ waiverId, data }: { waiverId: string; data: WaiverUpdate }) =>
            waiverApi.update(waiverId, data),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: waiverKeys.all });
            invalidateWaiverDependents(queryClient);
        }
    })
}

export const useDeleteWaiver = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: waiverApi.delete,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: waiverKeys.all });
            invalidateWaiverDependents(queryClient);
        }
    })
}

export const useWaiverList = (
    projectId: string | undefined,
    options?: {
        search?: string;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
        orphaned?: boolean;
        active?: boolean;
    }
) => {
    const { search, sortBy = 'created_at', sortOrder = 'desc', orphaned, active } = options || {};

    return useInfiniteQuery({
        queryKey: projectId
            ? waiverKeys.projectWithParams(projectId, search, sortBy, sortOrder, orphaned, active)
            : waiverKeys.globalWithParams(search, sortBy, sortOrder, orphaned),
        queryFn: ({ pageParam }) => waiverApi.getAll({
            ...(projectId ? { project_id: projectId } : { global_only: true }),
            skip: pageParam,
            limit: DEFAULT_PAGE_SIZE,
            search,
            sort_by: sortBy,
            sort_order: sortOrder,
            orphaned,
            active,
        }),
        initialPageParam: 0,
        getNextPageParam: (lastPage) => {
            const nextSkip = lastPage.page * lastPage.size;
            return nextSkip < lastPage.total ? nextSkip : undefined;
        },
        placeholderData: keepPreviousData,
    });
}

export const useWaiverById = (waiverId: string | undefined) => {
    return useQuery({
        queryKey: ['waivers', 'by-id', waiverId],
        queryFn: () => {
            if (!waiverId) throw new Error('waiverId is required');
            return waiverApi.getById(waiverId);
        },
        enabled: !!waiverId,
    });
};
