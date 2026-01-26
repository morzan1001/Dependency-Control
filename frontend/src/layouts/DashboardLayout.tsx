import { Outlet, Link, useLocation } from 'react-router-dom'
import { LayoutDashboard, Users, FolderGit2, LogOut, UserCog, User, Settings, BarChart3, Megaphone, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/context'
import { ANALYTICS_PERMISSIONS } from '@/lib/constants'

interface NavItem {
  href: string
  label: string
  icon: LucideIcon
  show: boolean
}

export default function DashboardLayout() {
  const location = useLocation()
  const { logout, hasPermission } = useAuth()

  const hasAnyPermission = (permissions: readonly string[]) =>
    permissions.some(p => hasPermission(p))

  const navItems: NavItem[] = [
    {
      href: '/dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
      show: true
    },
    {
      href: '/projects',
      label: 'Projects',
      icon: FolderGit2,
      show: hasPermission('project:read') || hasPermission('project:read_all')
    },
    {
      href: '/analytics',
      label: 'Analytics',
      icon: BarChart3,
      show: hasAnyPermission(ANALYTICS_PERMISSIONS)
    },
    {
      href: '/teams',
      label: 'Teams',
      icon: Users,
      show: hasPermission('team:read') || hasPermission('team:read_all')
    },
    {
      href: '/users',
      label: 'Users',
      icon: UserCog,
      show: hasPermission('user:manage') || hasPermission('user:read_all')
    },
    {
      href: '/broadcasts',
      label: 'Broadcasts',
      icon: Megaphone,
      show: hasPermission('notifications:broadcast') || hasPermission('system:manage')
    },
    {
      href: '/settings',
      label: 'Settings',
      icon: Settings,
      show: hasPermission('system:manage')
    },
  ].filter(item => item.show)

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar */}
      <aside className="w-64 border-r bg-card flex flex-col">
        <div className="p-6 flex items-center gap-3">
          <img src="/logo.png" alt="Logo" className="h-8 w-auto object-contain" />
          <h1 className="text-xl font-bold">Dependency Control</h1>
        </div>
        <nav className="space-y-1 px-4 flex-1">
          {navItems.map((item) => {
            const Icon = item.icon
            return (
              <Link
                key={item.href}
                to={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  location.pathname.startsWith(item.href)
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                )}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </Link>
            )
          })}
        </nav>
        <div className="p-4 space-y-2">
          <Link
            to="/profile"
            className={cn(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
              location.pathname === '/profile'
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
            )}
          >
            <User className="h-4 w-4" />
            Profile
          </Link>
          <Button variant="outline" className="w-full justify-start gap-3" onClick={logout}>
            <LogOut className="h-4 w-4" />
            Logout
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto">
        <div className="p-8 min-h-full">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
