import { Suspense, useState } from 'react'
import { Outlet, Link, useLocation } from 'react-router-dom'
import { LayoutDashboard, Users, FolderGit2, LogOut, UserCog, User, Settings, BarChart3, Megaphone, Archive, ShieldAlert, MessageSquare, Menu, X, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useAuth } from '@/context'
import { useAppConfig } from '@/hooks/queries/use-system'
import { ANALYTICS_PERMISSIONS } from '@/lib/constants'

interface NavItem {
  href: string
  label: string
  icon: LucideIcon
  show: boolean
  exact?: boolean
}

export default function DashboardLayout() {
  const location = useLocation()
  const { logout, hasPermission } = useAuth()
  const { data: appConfig } = useAppConfig()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const closeSidebar = () => setSidebarOpen(false)

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
      href: '/chat',
      label: 'Chat',
      icon: MessageSquare,
      show: hasPermission('chat:access') && (appConfig?.chat_enabled ?? false)
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
      show: hasPermission('user:read_all')
    },
    {
      href: '/archives',
      label: 'Archives',
      icon: Archive,
      show: hasPermission('archive:read_all') && appConfig?.archive_enabled === true
    },
    {
      href: '/waivers',
      label: 'Waivers',
      icon: ShieldAlert,
      show: hasPermission('waiver:manage')
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
      show: hasPermission('system:manage'),
      exact: true
    },
  ].filter(item => item.show)

  return (
    <div className="flex h-screen bg-background">
      {/* Backdrop for the mobile drawer. */}
      {sidebarOpen && (
        <button
          type="button"
          aria-label="Close menu"
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Off-canvas below lg, static from lg up. */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r bg-card transition-transform duration-200",
          "lg:static lg:translate-x-0",
          sidebarOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="p-6 flex items-center gap-3">
          <img src="/logo.png" alt="Logo" className="h-8 w-auto object-contain" />
          <h1 className="text-xl font-bold">Dependency Control</h1>
          <Button
            variant="ghost"
            size="icon"
            className="ml-auto lg:hidden"
            aria-label="Close menu"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="h-5 w-5" />
          </Button>
        </div>
        <nav className="space-y-1 px-4 flex-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = item.exact
              ? location.pathname === item.href
              : location.pathname.startsWith(item.href)
            return (
              <Link
                key={item.href}
                to={item.href}
                onClick={closeSidebar}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  isActive
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
            onClick={closeSidebar}
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

      {/* min-w-0 lets the content column shrink so inner tables scroll instead of forcing overflow. */}
      <div className="flex flex-1 flex-col min-w-0">
        {/* Mobile top bar with the menu toggle; the sidebar is always visible from lg up. */}
        <header className="flex items-center gap-3 border-b bg-card p-4 lg:hidden">
          <Button
            variant="ghost"
            size="icon"
            aria-label="Open menu"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="h-5 w-5" />
          </Button>
          <img src="/logo.png" alt="Logo" className="h-6 w-auto object-contain" />
          <span className="font-semibold">Dependency Control</span>
        </header>

        {/* Suspense wraps only the Outlet so a lazy route's chunk load keeps the sidebar chrome mounted. */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden">
          <div className="p-4 lg:p-8">
            <Suspense
              fallback={
                <div className="space-y-4">
                  <Skeleton className="h-8 w-48" />
                  <Skeleton className="h-32 w-full" />
                </div>
              }
            >
              <Outlet />
            </Suspense>
          </div>
        </main>
      </div>
    </div>
  )
}
