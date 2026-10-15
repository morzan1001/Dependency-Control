export interface TeamMember {
  user_id: string;
  username?: string;
  role: string;
  // "manual", or the "<provider>:<instance id>" of the sync that owns the entry.
  source?: string;
}

// A provider's next sync restores its entries, so the UI names an owner's source; each instance replaces only its own.
type TeamSourceProvider = 'gitlab' | 'github';
export type TeamSource = 'manual' | `${TeamSourceProvider}:${string}`;

export interface TeamRef {
  id: string;
  name: string;
}

// The numeric id identifies the group or team; slug and path move on rename, so they are display-only.
export interface TeamGitHubBinding {
  provider: 'github';
  instance_id: string;
  external_id: number;
  org: string;
  slug?: string | null;
}

export interface TeamGitLabBinding {
  provider: 'gitlab';
  instance_id: string;
  external_id: number;
  path?: string | null;
}

export type TeamBinding = TeamGitHubBinding | TeamGitLabBinding;

export type BindingProvider = TeamBinding['provider'];

export type TeamBindingRequest = Omit<TeamGitHubBinding, 'slug'> | Omit<TeamGitLabBinding, 'path'>;

export interface Team {
  id: string;
  name: string;
  description?: string;
  members: TeamMember[];
  created_at: string;
  updated_at: string;
  // One entry per instance, of either provider, in any number.
  bindings: TeamBinding[];
}

export interface TeamCreate {
  name: string;
  description?: string;
}

export interface TeamMemberCreate {
  email: string;
  role: string;
}
