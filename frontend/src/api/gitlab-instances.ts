import { createInstanceApi } from '@/api/client';
import {
  GitLabInstance,
  GitLabInstanceCreate,
  GitLabInstanceUpdate,
  GitLabInstanceList,
  GitLabInstanceTestConnectionResponse,
} from '@/types/gitlab';

export const gitlabInstancesApi = createInstanceApi<
  GitLabInstance,
  GitLabInstanceCreate,
  GitLabInstanceUpdate,
  GitLabInstanceList,
  GitLabInstanceTestConnectionResponse
>('/gitlab-instances');
