import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';

import { releaseApi } from '@/api/releases';
import { SMALL_PAGE_SIZE } from '@/lib/constants';
import type { MarkReleasePayload } from '@/types/release';
import { analyticsKeys } from './use-analytics';
import { scanKeys } from './use-scans';

const RELEASES_STALE_TIME_MS = 30_000;

export const releaseKeys = {
    all: ['releases'] as const,
    project: (projectId: string) => [...releaseKeys.all, 'project', projectId] as const,
    list: (projectId: string, environment?: string, limit: number = SMALL_PAGE_SIZE) =>
        [...releaseKeys.project(projectId), 'list', environment ?? null, limit] as const,
};

// Analytics in release mode and the scan list's release filter both read what a mark just changed.
const invalidateReleaseDependents = (queryClient: QueryClient, projectId: string) => {
    queryClient.invalidateQueries({ queryKey: releaseKeys.project(projectId) });
    queryClient.invalidateQueries({ queryKey: scanKeys.project(projectId) });
    queryClient.invalidateQueries({ queryKey: scanKeys.details() });
    queryClient.invalidateQueries({ queryKey: analyticsKeys.all });
};

export const useProjectReleases = (
    projectId: string,
    environment?: string,
    limit: number = SMALL_PAGE_SIZE,
) => {
    return useQuery({
        queryKey: releaseKeys.list(projectId, environment, limit),
        queryFn: () => releaseApi.list(projectId, { environment, limit }),
        enabled: !!projectId,
        staleTime: RELEASES_STALE_TIME_MS,
    });
}

export const useMarkRelease = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ projectId, payload }: { projectId: string; payload: MarkReleasePayload }) =>
            releaseApi.mark(projectId, payload),
        onSuccess: (_, variables) => {
            invalidateReleaseDependents(queryClient, variables.projectId);
        }
    })
}

export const useUnmarkRelease = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ projectId, scanId, environment }: { projectId: string; scanId: string; environment: string }) =>
            releaseApi.unmark(projectId, scanId, environment),
        onSuccess: (_, variables) => {
            invalidateReleaseDependents(queryClient, variables.projectId);
        }
    })
}
