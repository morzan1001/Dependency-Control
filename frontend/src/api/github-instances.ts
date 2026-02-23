import { createInstanceApi } from '@/api/client';
import {
  GitHubInstance,
  GitHubInstanceCreate,
  GitHubInstanceUpdate,
  GitHubInstanceList,
  GitHubInstanceTestConnectionResponse,
} from '@/types/github';

export const githubInstancesApi = createInstanceApi<
  GitHubInstance,
  GitHubInstanceCreate,
  GitHubInstanceUpdate,
  GitHubInstanceList,
  GitHubInstanceTestConnectionResponse
>('/github-instances');
