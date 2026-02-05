import { ObjectId } from './common';

export interface TeamMember {
  user_id: ObjectId;
  username?: string;
  role: string;
}

export interface Team {
  id: ObjectId;
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
