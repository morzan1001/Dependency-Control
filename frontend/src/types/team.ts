export interface TeamMember {
  user_id: string;
  username?: string;
  role: string;
}

export interface Team {
  _id: string; // Using string id instead of MongoDB ObjectId type for frontend
  id?: string; // Alias for _id for some components
  name: string;
  description?: string;
  members: TeamMember[];
  created_at: string;
  updated_at: string;
}

export interface TeamCreate {
  name: string;
  description?: string;
}

export interface TeamMemberCreate {
  email: string;
  role: string;
}
