import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Login from './pages/Login'
import Signup from './pages/Signup'
import Dashboard from './pages/Dashboard'
import UsersPage from './pages/Users'
import TeamsPage from './pages/Teams'
import ProjectsPage from './pages/Projects'
import ProjectDetails from './pages/ProjectDetails'
import ScanDetails from './pages/ScanDetails'
import ProfilePage from './pages/Profile'
import SystemSettings from './pages/SystemSettings'
import SearchPage from './pages/Search'
import DashboardLayout from './layouts/DashboardLayout'
import { AuthProvider, useAuth, RequirePermission } from './context/AuthContext'
import { Toaster } from "@/components/ui/sonner"
import { ThemeProvider } from "next-themes"
import { Spinner } from "@/components/ui/spinner"
import { getPublicConfig } from '@/lib/api'
import { useState, useEffect } from 'react'

const queryClient = new QueryClient()

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Spinner size={48} />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}

function SignupRoute() {
  const [enabled, setEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    getPublicConfig().then(config => setEnabled(config.allow_public_registration)).catch(() => setEnabled(false));
  }, []);

  if (enabled === null) return <div className="flex h-screen items-center justify-center"><Spinner size={48} /></div>;
  
  if (!enabled) return <Navigate to="/login" replace />;

  return <Signup />;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<SignupRoute />} />
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
        <Route path="/search/dependencies" element={<SearchPage />} />
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
