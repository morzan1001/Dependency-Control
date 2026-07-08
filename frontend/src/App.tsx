import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider, QueryCache, MutationCache } from '@tanstack/react-query'
import Login from './pages/Login'
import ResetPassword from './pages/ResetPassword'
import Signup from './pages/Signup'
import VerifyEmail from './pages/VerifyEmail'
import ResendVerification from './pages/ResendVerification'
import Setup2FA from './pages/Setup2FA'
import AcceptInvite from './pages/AcceptInvite'
import LoginCallback from './pages/LoginCallback'
// Authenticated pages are code-split to keep chart/markdown deps out of the initial bundle.
const Dashboard = lazy(() => import('./pages/Dashboard'))
const UsersPage = lazy(() => import('./pages/Users'))
const TeamsPage = lazy(() => import('./pages/Teams'))
const ProjectsPage = lazy(() => import('./pages/Projects'))
const ProjectDetails = lazy(() => import('./pages/ProjectDetails'))
const ScanDetails = lazy(() => import('./pages/ScanDetails'))
const ProfilePage = lazy(() => import('./pages/Profile'))
const SystemSettings = lazy(() => import('./pages/SystemSettings'))
const Broadcasts = lazy(() => import('./pages/Broadcasts'))
const SearchPage = lazy(() => import('./pages/Search'))
const AnalyticsPage = lazy(() => import('./pages/Analytics'))
const ArchivesPage = lazy(() => import('./pages/Archives'))
const GlobalWaivers = lazy(() => import('./pages/GlobalWaivers'))
const Chat = lazy(() => import('./pages/Chat'))

import DashboardLayout from './layouts/DashboardLayout'
import { AuthProvider, RequirePermission, useAuth } from './context'
import { Toaster } from "@/components/ui/sonner"
import { toast } from "sonner"
import { ThemeProvider } from "next-themes"
import { Skeleton } from "@/components/ui/skeleton"
import { ErrorBoundary } from "@/components/ErrorBoundary"
import { systemApi } from '@/api/system'
import { ANALYTICS_ROUTE_PERMISSIONS } from '@/lib/constants'
import { lazy, Suspense, useState, useEffect } from 'react'

const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error: Error) => {
      const axiosError = error as { response?: { status?: number } }
      if (axiosError.response?.status && axiosError.response.status >= 500) {
        toast.error("Server Error", { description: "Something went wrong on the server." })
      }
    }
  }),
  mutationCache: new MutationCache({
    onError: (_error: Error) => {
      // Mutations handle their own error display.
    }
  }),
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

function Force2FAGuard({ children }: { children: React.ReactNode }) {
  const { permissions } = useAuth();
  const location = useLocation();

  if (permissions.length === 1 && permissions[0] === 'auth:setup_2fa') {
      if (location.pathname === '/setup-2fa') {
          return <>{children}</>;
      }
      return <Navigate to="/setup-2fa" replace />;
  }

  if (location.pathname === '/setup-2fa' && !(permissions.length === 1 && permissions[0] === 'auth:setup_2fa')) {
      return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="space-y-4 flex flex-col items-center">
          <Skeleton className="h-12 w-12 rounded-full" />
          <Skeleton className="h-4 w-32" />
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <Force2FAGuard>{children}</Force2FAGuard>;
}

function SignupRoute() {
  const [enabled, setEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    systemApi.getPublicConfig().then(config => setEnabled(config.allow_public_registration)).catch(() => setEnabled(false));
  }, []);

  if (enabled === null) return (
    <div className="flex h-screen items-center justify-center">
      <div className="space-y-4 flex flex-col items-center">
        <Skeleton className="h-12 w-12 rounded-full" />
        <Skeleton className="h-4 w-32" />
      </div>
    </div>
  );
  
  if (!enabled) return <Navigate to="/login" replace />;

  return <Signup />;
}

function PageLoader() {
  return (
    <div className="flex h-screen items-center justify-center">
      <div className="space-y-4 flex flex-col items-center">
        <Skeleton className="h-12 w-12 rounded-full" />
        <Skeleton className="h-4 w-32" />
      </div>
    </div>
  );
}

function AppRoutes() {
  return (
    <Suspense fallback={<PageLoader />}>
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/login/callback" element={<LoginCallback />} />
      <Route path="/signup" element={<SignupRoute />} />
      <Route path="/verify-email" element={<VerifyEmail />} />
      <Route path="/resend-verification" element={<ResendVerification />} />
      <Route path="/accept-invite" element={<AcceptInvite />} />
      <Route path="/setup-2fa" element={
        <ProtectedRoute>
          <Setup2FA />
        </ProtectedRoute>
      } />
      <Route element={
        <ProtectedRoute>
          <ErrorBoundary>
            <DashboardLayout />
          </ErrorBoundary>
        </ProtectedRoute>
      }>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/projects" element={
          <RequirePermission permission={['project:read', 'project:read_all']}>
            <ProjectsPage />
          </RequirePermission>
        } />
        <Route path="/projects/:id" element={
          <RequirePermission permission={['project:read', 'project:read_all']}>
            <ProjectDetails />
          </RequirePermission>
        } />
        <Route path="/projects/:projectId/scans/:scanId" element={
          <RequirePermission permission={['project:read', 'project:read_all']}>
            <ScanDetails />
          </RequirePermission>
        } />
        <Route path="/teams" element={
          <RequirePermission permission={['team:read', 'team:read_all']}>
            <TeamsPage />
          </RequirePermission>
        } />
        <Route path="/profile" element={<ProfilePage />} />
        <Route path="/users" element={
          <RequirePermission permission={['user:read_all']}>
            <UsersPage />
          </RequirePermission>
        } />
        <Route path="/search/dependencies" element={
          <RequirePermission permission={['analytics:search', 'analytics:read']}>
            <SearchPage />
          </RequirePermission>
        } />
        <Route path="/analytics" element={
          <RequirePermission permission={[...ANALYTICS_ROUTE_PERMISSIONS]}>
            <AnalyticsPage />
          </RequirePermission>
        } />
        <Route path="/settings" element={
          <RequirePermission permission="system:manage">
            <SystemSettings />
          </RequirePermission>
        } />
        <Route path="/broadcasts" element={
          <RequirePermission permission={['notifications:broadcast', 'system:manage']}>
            <Broadcasts />
          </RequirePermission>
        } />
        <Route path="/archives" element={
          <RequirePermission permission="archive:read_all">
            <ArchivesPage />
          </RequirePermission>
        } />
        <Route path="/waivers" element={
          <RequirePermission permission="waiver:manage">
            <GlobalWaivers />
          </RequirePermission>
        } />
        <Route path="/chat" element={
          <RequirePermission permission="chat:access">
            <Chat />
          </RequirePermission>
        } />
      </Route>
    </Routes>
    </Suspense>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
        <BrowserRouter>
          <AuthProvider>
            <AppRoutes />
            <Toaster />
          </AuthProvider>
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  )
}

export default App
