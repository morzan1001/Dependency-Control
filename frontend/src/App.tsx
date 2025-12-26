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
import Dashboard from './pages/Dashboard'
import UsersPage from './pages/Users'
import TeamsPage from './pages/Teams'
import ProjectsPage from './pages/Projects'
import ProjectDetails from './pages/ProjectDetails'
import ScanDetails from './pages/ScanDetails'
import ProfilePage from './pages/Profile'
import SystemSettings from './pages/SystemSettings'
import SearchPage from './pages/Search'
import AnalyticsPage from './pages/Analytics'
import DashboardLayout from './layouts/DashboardLayout'
import { AuthProvider, useAuth, RequirePermission } from './context/AuthContext'
import { Toaster } from "@/components/ui/sonner"
import { toast } from "sonner"
import { ThemeProvider } from "next-themes"
import { Skeleton } from "@/components/ui/skeleton"
import { getPublicConfig } from '@/lib/api'
import { useState, useEffect } from 'react'
import { AxiosError } from 'axios'

interface ApiErrorResponse {
  detail?: string;
  message?: string;
}

const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error: Error) => {
      const axiosError = error as AxiosError<ApiErrorResponse>
      if (axiosError.response?.status && axiosError.response.status >= 500) {
        toast.error("Server Error", { description: "Something went wrong on the server." })
      }
    }
  }),
  mutationCache: new MutationCache({
    onError: (_error: Error) => {
      // Mutations handle their own error display
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

  // Check for limited token first
  if (permissions.length === 1 && permissions[0] === 'auth:setup_2fa') {
      if (location.pathname === '/setup-2fa') {
          return <>{children}</>;
      }
      return <Navigate to="/setup-2fa" replace />;
  }

  // If we are on setup page but have full permissions, redirect to dashboard
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
    getPublicConfig().then(config => setEnabled(config.allow_public_registration)).catch(() => setEnabled(false));
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

function AppRoutes() {
  return (
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
          <DashboardLayout />
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
          <RequirePermission permission={['user:manage', 'user:read_all']}>
            <UsersPage />
          </RequirePermission>
        } />
        <Route path="/search/dependencies" element={
          <RequirePermission permission={['analytics:search', 'analytics:read']}>
            <SearchPage />
          </RequirePermission>
        } />
        <Route path="/analytics" element={
          <RequirePermission permission={['analytics:read', 'analytics:summary', 'analytics:dependencies', 'analytics:tree', 'analytics:impact', 'analytics:hotspots', 'analytics:search']}>
            <AnalyticsPage />
          </RequirePermission>
        } />
        <Route path="/settings" element={
          <RequirePermission permission="system:manage">
            <SystemSettings />
          </RequirePermission>
        } />
        {/* Add other routes here */}
      </Route>
    </Routes>
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
