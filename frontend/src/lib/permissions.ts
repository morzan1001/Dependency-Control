export const Permissions = {
  // System Management
  SYSTEM_MANAGE: "system:manage",

  // User Management
  USER_CREATE: "user:create",
  USER_READ: "user:read",
  USER_READ_ALL: "user:read_all",
  USER_UPDATE: "user:update",
  USER_DELETE: "user:delete",
  USER_MANAGE_PERMISSIONS: "user:manage_permissions",

  // Team Management
  TEAM_CREATE: "team:create",
  TEAM_READ: "team:read",
  TEAM_READ_ALL: "team:read_all",
  TEAM_UPDATE: "team:update",
  TEAM_DELETE: "team:delete",

  // Project Management
  PROJECT_CREATE: "project:create",
  PROJECT_READ: "project:read",
  PROJECT_READ_ALL: "project:read_all",
  PROJECT_UPDATE: "project:update",
  PROJECT_DELETE: "project:delete",

  // Analytics
  ANALYTICS_READ: "analytics:read",
  ANALYTICS_SUMMARY: "analytics:summary",
  ANALYTICS_DEPENDENCIES: "analytics:dependencies",
  ANALYTICS_TREE: "analytics:tree",
  ANALYTICS_IMPACT: "analytics:impact",
  ANALYTICS_HOTSPOTS: "analytics:hotspots",
  ANALYTICS_SEARCH: "analytics:search",
  ANALYTICS_RECOMMENDATIONS: "analytics:recommendations",
  ANALYTICS_GLOBAL: "analytics:global",

  // Notifications
  NOTIFICATIONS_BROADCAST: "notifications:broadcast",

  // Waivers
  WAIVER_READ: "waiver:read",
  WAIVER_READ_ALL: "waiver:read_all",
  WAIVER_MANAGE: "waiver:manage",
  WAIVER_DELETE: "waiver:delete",

  // Webhooks
  WEBHOOK_CREATE: "webhook:create",
  WEBHOOK_READ: "webhook:read",
  WEBHOOK_UPDATE: "webhook:update",
  WEBHOOK_DELETE: "webhook:delete",

  // Archives
  ARCHIVE_READ: "archive:read",
  ARCHIVE_RESTORE: "archive:restore",
  ARCHIVE_DOWNLOAD: "archive:download",
  ARCHIVE_READ_ALL: "archive:read_all",

  // Chat
  CHAT_ACCESS: "chat:access",
  CHAT_HISTORY_READ: "chat:history_read",
  CHAT_HISTORY_DELETE: "chat:history_delete",

  // MCP — issue API keys for external LLM clients
  MCP_ACCESS: "mcp:access",
} as const;

export type Permission = (typeof Permissions)[keyof typeof Permissions];

// All permissions in the system (excluding internal/special permissions like auth:setup_2fa)
export const ALL_PERMISSIONS: Permission[] = [
  // System
  Permissions.SYSTEM_MANAGE,
  // User
  Permissions.USER_CREATE,
  Permissions.USER_READ,
  Permissions.USER_READ_ALL,
  Permissions.USER_UPDATE,
  Permissions.USER_DELETE,
  Permissions.USER_MANAGE_PERMISSIONS,
  // Team
  Permissions.TEAM_CREATE,
  Permissions.TEAM_READ,
  Permissions.TEAM_READ_ALL,
  Permissions.TEAM_UPDATE,
  Permissions.TEAM_DELETE,
  // Project
  Permissions.PROJECT_CREATE,
  Permissions.PROJECT_READ,
  Permissions.PROJECT_READ_ALL,
  Permissions.PROJECT_UPDATE,
  Permissions.PROJECT_DELETE,
  // Analytics
  Permissions.ANALYTICS_READ,
  Permissions.ANALYTICS_SUMMARY,
  Permissions.ANALYTICS_DEPENDENCIES,
  Permissions.ANALYTICS_TREE,
  Permissions.ANALYTICS_IMPACT,
  Permissions.ANALYTICS_HOTSPOTS,
  Permissions.ANALYTICS_SEARCH,
  Permissions.ANALYTICS_RECOMMENDATIONS,
  Permissions.ANALYTICS_GLOBAL,
  // Notifications
  Permissions.NOTIFICATIONS_BROADCAST,
  // Waivers
  Permissions.WAIVER_READ,
  Permissions.WAIVER_READ_ALL,
  Permissions.WAIVER_MANAGE,
  Permissions.WAIVER_DELETE,
  // Webhooks
  Permissions.WEBHOOK_CREATE,
  Permissions.WEBHOOK_READ,
  Permissions.WEBHOOK_UPDATE,
  Permissions.WEBHOOK_DELETE,
  // Archives
  Permissions.ARCHIVE_READ,
  Permissions.ARCHIVE_RESTORE,
  Permissions.ARCHIVE_DOWNLOAD,
  Permissions.ARCHIVE_READ_ALL,
  // Chat
  Permissions.CHAT_ACCESS,
  Permissions.CHAT_HISTORY_READ,
  Permissions.CHAT_HISTORY_DELETE,
  // MCP
  Permissions.MCP_ACCESS,
];

// Admin: All permissions
export const PRESET_ADMIN: Permission[] = [...ALL_PERMISSIONS];

// Regular User: Can create/manage own projects and teams, view analytics
export const PRESET_USER: Permission[] = [
  // User - can view own profile
  Permissions.USER_READ,
  // Team - can create and view teams
  Permissions.TEAM_CREATE,
  Permissions.TEAM_READ,
  // Project - can create and view projects
  Permissions.PROJECT_CREATE,
  Permissions.PROJECT_READ,
  // Analytics - can view all analytics for accessible projects
  Permissions.ANALYTICS_READ,
  Permissions.ANALYTICS_SUMMARY,
  Permissions.ANALYTICS_DEPENDENCIES,
  Permissions.ANALYTICS_TREE,
  Permissions.ANALYTICS_IMPACT,
  Permissions.ANALYTICS_HOTSPOTS,
  Permissions.ANALYTICS_SEARCH,
  Permissions.ANALYTICS_RECOMMENDATIONS,
  // Waivers - can view own waivers
  Permissions.WAIVER_READ,
  // Archives - can view and download archives for accessible projects
  Permissions.ARCHIVE_READ,
  Permissions.ARCHIVE_DOWNLOAD,
  // Webhooks - managed via project roles (admin), no global override needed
];

// Viewer: Read-only access
export const PRESET_VIEWER: Permission[] = [
  // User - can view own profile
  Permissions.USER_READ,
  // Team - can view teams they belong to
  Permissions.TEAM_READ,
  // Project - can view projects they have access to
  Permissions.PROJECT_READ,
  // Analytics - can view summaries
  Permissions.ANALYTICS_READ,
  Permissions.ANALYTICS_SUMMARY,
  // Waivers - can view waivers
  Permissions.WAIVER_READ,
  // Archives - can view archives
  Permissions.ARCHIVE_READ,
];

export interface PermissionItem {
  id: string;
  label: string;
  description: string;
}

export interface PermissionGroup {
  id: string;
  title: string;
  description: string;
  permissions: PermissionItem[];
}

export const PERMISSION_GROUPS: PermissionGroup[] = [
  {
    id: "system",
    title: "System & Administration",
    description: "System-wide administrative permissions",
    permissions: [
      {
        id: Permissions.SYSTEM_MANAGE,
        label: "System Settings",
        description: "Manage system configurations",
      },
    ],
  },
  {
    id: "user",
    title: "User Management",
    description: "Permissions for managing users",
    permissions: [
      {
        id: Permissions.USER_CREATE,
        label: "Create Users",
        description: "Create new user accounts",
      },
      {
        id: Permissions.USER_READ,
        label: "Read User Details",
        description: "View own user profile",
      },
      {
        id: Permissions.USER_READ_ALL,
        label: "List All Users",
        description: "View list of all users in the system",
      },
      {
        id: Permissions.USER_UPDATE,
        label: "Update Users",
        description: "Update user profiles",
      },
      {
        id: Permissions.USER_DELETE,
        label: "Delete Users",
        description: "Delete users",
      },
      {
        id: Permissions.USER_MANAGE_PERMISSIONS,
        label: "Manage User Permissions",
        description: "Grant or revoke permissions on user accounts",
      },
    ],
  },
  {
    id: "team",
    title: "Team Management",
    description: "Permissions for managing teams",
    permissions: [
      {
        id: Permissions.TEAM_CREATE,
        label: "Create Teams",
        description: "Create new teams",
      },
      {
        id: Permissions.TEAM_READ,
        label: "Read Own Teams",
        description: "View teams you are a member of",
      },
      {
        id: Permissions.TEAM_READ_ALL,
        label: "Read All Teams",
        description: "View all teams in the system",
      },
      {
        id: Permissions.TEAM_UPDATE,
        label: "Update Teams",
        description: "Update any team",
      },
      {
        id: Permissions.TEAM_DELETE,
        label: "Delete Teams",
        description: "Delete any team",
      },
    ],
  },
  {
    id: "project",
    title: "Project Management",
    description: "Permissions for managing projects",
    permissions: [
      {
        id: Permissions.PROJECT_CREATE,
        label: "Create Projects",
        description: "Create new projects",
      },
      {
        id: Permissions.PROJECT_READ,
        label: "Read Own Projects",
        description: "View projects you are a member of",
      },
      {
        id: Permissions.PROJECT_READ_ALL,
        label: "Read All Projects",
        description: "View all projects in the system",
      },
      {
        id: Permissions.PROJECT_UPDATE,
        label: "Update Projects",
        description: "Update any project",
      },
      {
        id: Permissions.PROJECT_DELETE,
        label: "Delete Projects",
        description: "Delete any project",
      },
    ],
  },
  {
    id: "analytics",
    title: "Analytics & Insights",
    description: "Permissions for viewing analytics",
    permissions: [
      {
        id: Permissions.ANALYTICS_READ,
        label: "View Analytics",
        description: "Access the Analytics dashboard and view statistics",
      },
      {
        id: Permissions.ANALYTICS_SUMMARY,
        label: "View Summary",
        description: "View analytics summary and overview data",
      },
      {
        id: Permissions.ANALYTICS_DEPENDENCIES,
        label: "View Dependencies",
        description: "View cross-project dependency analysis",
      },
      {
        id: Permissions.ANALYTICS_TREE,
        label: "View Dependency Tree",
        description: "View dependency tree visualization",
      },
      {
        id: Permissions.ANALYTICS_IMPACT,
        label: "View Impact Analysis",
        description: "View impact analysis and fix recommendations",
      },
      {
        id: Permissions.ANALYTICS_HOTSPOTS,
        label: "View Hotspots",
        description: "View vulnerability hotspots across projects",
      },
      {
        id: Permissions.ANALYTICS_SEARCH,
        label: "Cross-Project Search",
        description: "Search dependencies across all accessible projects",
      },
      {
        id: Permissions.ANALYTICS_RECOMMENDATIONS,
        label: "View Recommendations",
        description: "View security recommendations",
      },
      {
        id: Permissions.ANALYTICS_GLOBAL,
        label: "Global Analytics",
        description: "Query analytics across all projects system-wide",
      },
    ],
  },
  {
    id: "notifications",
    title: "Notifications & Broadcasts",
    description: "Permissions for notifications",
    permissions: [
      {
        id: Permissions.NOTIFICATIONS_BROADCAST,
        label: "Manage Broadcasts",
        description: "Send system-wide broadcast notifications",
      },
    ],
  },
  {
    id: "waiver",
    title: "Security & Compliance",
    description: "Permissions for managing waivers",
    permissions: [
      {
        id: Permissions.WAIVER_READ,
        label: "Read Own Waivers",
        description: "View waivers for your projects",
      },
      {
        id: Permissions.WAIVER_READ_ALL,
        label: "Read All Waivers",
        description: "View all waivers in the system",
      },
      {
        id: Permissions.WAIVER_MANAGE,
        label: "Manage Waivers",
        description: "Create global waivers",
      },
      {
        id: Permissions.WAIVER_DELETE,
        label: "Delete Waivers",
        description: "Delete any waiver",
      },
    ],
  },
  {
    id: "webhook",
    title: "Integrations",
    description: "Permissions for managing webhooks",
    permissions: [
      {
        id: Permissions.WEBHOOK_CREATE,
        label: "Create Webhooks",
        description: "Create webhooks for any project",
      },
      {
        id: Permissions.WEBHOOK_READ,
        label: "Read Webhooks",
        description: "View webhook configurations",
      },
      {
        id: Permissions.WEBHOOK_UPDATE,
        label: "Update Webhooks",
        description: "Modify webhook configurations",
      },
      {
        id: Permissions.WEBHOOK_DELETE,
        label: "Delete Webhooks",
        description: "Delete any webhook",
      },
    ],
  },
  {
    id: "archive",
    title: "Archives",
    description: "Permissions for managing scan archives",
    permissions: [
      {
        id: Permissions.ARCHIVE_READ,
        label: "Read Archives",
        description: "View archived scans for accessible projects",
      },
      {
        id: Permissions.ARCHIVE_RESTORE,
        label: "Restore Archives",
        description: "Restore archived scans back to the database",
      },
      {
        id: Permissions.ARCHIVE_DOWNLOAD,
        label: "Download Archives",
        description: "Download archived scan bundles",
      },
      {
        id: Permissions.ARCHIVE_READ_ALL,
        label: "Read All Archives",
        description: "View archives across all projects",
      },
    ],
  },
  {
    id: "chat",
    title: "Chat",
    description: "Permissions for the AI security assistant",
    permissions: [
      {
        id: Permissions.CHAT_ACCESS,
        label: "Chat Access",
        description: "Use the AI chat assistant and create conversations",
      },
      {
        id: Permissions.CHAT_HISTORY_READ,
        label: "Read Chat History",
        description: "View own past chat conversations",
      },
      {
        id: Permissions.CHAT_HISTORY_DELETE,
        label: "Delete Chat History",
        description: "Delete own chat conversations",
      },
    ],
  },
  {
    id: "mcp",
    title: "MCP (External LLM access)",
    description:
      "Lets a user mint personal API keys for external LLM clients (Claude Desktop, Cursor, custom bots) to call the DependencyControl tool surface over MCP.",
    permissions: [
      {
        id: Permissions.MCP_ACCESS,
        label: "MCP Access",
        description:
          "Create and manage personal MCP API keys and use them against /api/v1/mcp",
      },
    ],
  },
];

/** When `requireAll` is true, all required permissions must match; otherwise any one suffices. */
export function hasPermission(
  userPermissions: string[],
  required: string | string[],
  requireAll: boolean = false
): boolean {
  const requiredList = Array.isArray(required) ? required : [required];

  if (requireAll) {
    return requiredList.every((perm) => userPermissions.includes(perm));
  } else {
    return requiredList.some((perm) => userPermissions.includes(perm));
  }
}

export function getMissingPermissions(
  userPermissions: string[],
  required: string | string[]
): string[] {
  const requiredList = Array.isArray(required) ? required : [required];
  return requiredList.filter((perm) => !userPermissions.includes(perm));
}

export function getAllPermissionIds(): string[] {
  return PERMISSION_GROUPS.flatMap((group) =>
    group.permissions.map((p) => p.id)
  );
}
