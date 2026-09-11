export interface TeamMember {
  user_id: string;
  username?: string;
  role: string;
}

// Whoever established a team's ownership of a project. A provider's entry is restored by its next
// sync, so the UI has to say which kind an owner is before offering to remove it.
export type TeamSource = 'gitlab' | 'github' | 'manual';

// One owning team as the project list, the comparison rows and the chat tools name it.
export interface TeamRef {
  id: string;
  name: string;
}

export interface Team {
  id: string;
  name: string;
  description?: string;
  members: TeamMember[];
  created_at: string;
  updated_at: string;
  github_instance_id?: string | null;
  github_org?: string | null;
  github_team_id?: number | null;
  github_team_slug?: string | null;
}

export interface TeamGitHubBinding {
  github_instance_id: string;
  github_org: string;
  github_team_id: number;
}

export interface TeamCreate {
  name: string;
  description?: string;
}

export interface TeamMemberCreate {
  email: string;
  role: string;
}
