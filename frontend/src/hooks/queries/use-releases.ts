import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';

import { releaseApi } from '@/api/releases';
import { SMALL_PAGE_SIZE } from '@/lib/constants';
import type { MarkReleasePayload, ReleaseItem } from '@/types/release';
import { analyticsKeys } from './use-analytics';
import { scanKeys } from './use-scans';

const RELEASES_STALE_TIME_MS = 30_000;
const NO_RELEASES = 0;

// The endpoint answers newest-first across every environment, so one row is both the project's
// newest release and the answer to whether it releases at all.
export const LATEST_RELEASE_LIMIT = 1;

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

export interface LatestProjectRelease {
    latestRelease: ReleaseItem | undefined;
    // Whether the project reports releases at all. The release surfaces are hidden until it does,
    // because an empty one reads as a missing report rather than as a repo that does not release.
    hasReleases: boolean;
    isLoading: boolean;
}

// Three consumers, one query key, one request.
export const useLatestProjectRelease = (projectId: string): LatestProjectRelease => {
    const { data, isLoading } = useProjectReleases(projectId, undefined, LATEST_RELEASE_LIMIT);
    return {
        latestRelease: data?.items[0],
        hasReleases: (data?.total ?? NO_RELEASES) > NO_RELEASES,
        isLoading,
    };
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
