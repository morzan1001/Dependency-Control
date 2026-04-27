import { useMutation, useInfiniteQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { waiverApi } from '@/api/waivers';
import { WaiverUpdate } from '@/types/waiver';
import { DEFAULT_PAGE_SIZE } from '@/lib/constants';
import { scanKeys } from './use-scans';
import { analyticsKeys } from './use-analytics';
import { projectKeys } from './use-projects';

export const waiverKeys = {
    all: ['waivers'] as const,
    project: (projectId: string) => [...waiverKeys.all, 'project', projectId] as const,
    projectWithParams: (projectId: string, search?: string, sortBy?: string, sortOrder?: string) =>
        [...waiverKeys.project(projectId), { search, sortBy, sortOrder }] as const,
    global: ['waivers', 'global'] as const,
    globalWithParams: (search?: string, sortBy?: string, sortOrder?: string) =>
        ['waivers', 'global', { search, sortBy, sortOrder }] as const,
};

const invalidateWaiverDependents = (queryClient: QueryClient) => {
    queryClient.invalidateQueries({ queryKey: scanKeys.all });
    queryClient.invalidateQueries({ queryKey: analyticsKeys.all });
    queryClient.invalidateQueries({ queryKey: projectKeys.all });
};

export const useCreateWaiver = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: waiverApi.create,
        onSuccess: (_, variables) => {
            if (variables.project_id) {
                queryClient.invalidateQueries({ queryKey: waiverKeys.project(variables.project_id) });
            }
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

export const useProjectWaivers = (
    projectId: string,
    options?: {
        search?: string;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
    }
) => {
    const { search, sortBy = 'created_at', sortOrder = 'desc' } = options || {};

    return useInfiniteQuery({
        queryKey: waiverKeys.projectWithParams(projectId, search, sortBy, sortOrder),
        queryFn: async ({ pageParam = 0 }) => {
            return waiverApi.getByProject(projectId, {
                skip: pageParam,
                limit: DEFAULT_PAGE_SIZE,
                search,
                sort_by: sortBy,
                sort_order: sortOrder,
            });
        },
        initialPageParam: 0,
        getNextPageParam: (lastPage) => {
            const nextSkip = lastPage.page * lastPage.size;
            return nextSkip < lastPage.total ? nextSkip : undefined;
        },
        enabled: !!projectId,
    });
}

export const useGlobalWaivers = (
    options?: {
        search?: string;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
    }
) => {
    const { search, sortBy = 'created_at', sortOrder = 'desc' } = options || {};

    return useInfiniteQuery({
        queryKey: waiverKeys.globalWithParams(search, sortBy, sortOrder),
        queryFn: async ({ pageParam = 0 }) => {
            return waiverApi.getAll({
                global_only: true,
                skip: pageParam,
                limit: DEFAULT_PAGE_SIZE,
                search,
                sort_by: sortBy,
                sort_order: sortOrder,
            });
        },
        initialPageParam: 0,
        getNextPageParam: (lastPage) => {
            const nextSkip = lastPage.page * lastPage.size;
            return nextSkip < lastPage.total ? nextSkip : undefined;
        },
    });
}
