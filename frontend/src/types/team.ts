export interface TeamMember {
  user_id: string;
  username?: string;
  role: string;
}

// Whoever established a team's ownership of a project. A provider's entry is restored by its next
// sync, so the UI has to say which kind an owner is before offering to remove it. A provider entry
// names the instance too — two instances of one provider each replace only their own owners.
type TeamSourceProvider = 'gitlab' | 'github';
export type TeamSource = 'manual' | `${TeamSourceProvider}:${string}`;

// One owning team as the project list, the comparison rows and the chat tools name it.
export interface TeamRef {
  id: string;
  name: string;
}

// The numeric id identifies the group or team; the slug and the path move when one is renamed,
// so the server reads them back on every write and they are display only.
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
