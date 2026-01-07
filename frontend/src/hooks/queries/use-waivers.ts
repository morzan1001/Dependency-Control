import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { waiverApi } from '@/api/waivers';
import { WaiverCreate } from '@/types/waiver';

export const waiverKeys = {
    all: ['waivers'] as const,
    project: (projectId: string) => [...waiverKeys.all, 'project', projectId] as const,
};

export const useWaiver = () => {
    return {
        createWaiver: (data: WaiverCreate) => waiverApi.create(data),
        deleteWaiver: (waiverId: string) => waiverApi.delete(waiverId)
    }
}

export const useCreateWaiver = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: waiverApi.create,
        onSuccess: (_, variables) => {
            if (variables.project_id) {
                queryClient.invalidateQueries({ queryKey: waiverKeys.project(variables.project_id) });
            }
        }
    })
}

export const useDeleteWaiver = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: waiverApi.delete,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: waiverKeys.all });
        }
    })
}

export const useProjectWaivers = (projectId: string) => {
    return useQuery({
        queryKey: waiverKeys.project(projectId),
        queryFn: () => waiverApi.getAll(projectId),
        enabled: !!projectId
    });
}
