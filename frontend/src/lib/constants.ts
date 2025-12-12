export const PERMISSION_GROUPS = [
  {
    title: "System & Administration",
    permissions: [
      { id: "*", label: "Administrator", description: "Full access to all resources" },
      { id: "system:manage", label: "System Settings", description: "Manage system configurations" },
    ]
  },
  {
    title: "User Management",
    permissions: [
      { id: "user:read_all", label: "List All Users", description: "View list of all users in the system" },
      { id: "user:create", label: "Create Users", description: "Create new users" },
      { id: "user:read", label: "Read User Details", description: "View detailed user information" },
      { id: "user:update", label: "Update Users", description: "Update user profiles" },
      { id: "user:delete", label: "Delete Users", description: "Delete users" },
    ]
  },
  {
    title: "Team Management",
    permissions: [
      { id: "team:read_all", label: "Read All Teams", description: "View all teams in the system" },
      { id: "team:read", label: "Read Own Teams", description: "View teams you are a member of" },
      { id: "team:create", label: "Create Teams", description: "Create new teams" },
      { id: "team:update", label: "Update Teams", description: "Update any team" },
      { id: "team:delete", label: "Delete Teams", description: "Delete any team" },
    ]
  },
  {
    title: "Project Management",
    permissions: [
      { id: "project:read_all", label: "Read All Projects", description: "View all projects in the system" },
      { id: "project:read", label: "Read Own Projects", description: "View projects you are a member of" },
      { id: "project:create", label: "Create Projects", description: "Create new projects" },
      { id: "project:update", label: "Update Projects", description: "Update any project" },
    ]
  },
  {
    title: "Security & Compliance",
    permissions: [
      { id: "waiver:read_all", label: "Read All Waivers", description: "View all waivers in the system" },
      { id: "waiver:read", label: "Read Own Waivers", description: "View waivers for your projects" },
      { id: "waiver:manage", label: "Manage Waivers", description: "Create global waivers" },
      { id: "waiver:delete", label: "Delete Waivers", description: "Delete any waiver" },
    ]
  },
  {
    title: "Integrations",
    permissions: [
      { id: "webhook:create", label: "Create Webhooks", description: "Create webhooks for any project" },
      { id: "webhook:delete", label: "Delete Webhooks", description: "Delete any webhook" },
    ]
  }
];
