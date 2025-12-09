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
import DashboardLayout from './layouts/DashboardLayout'
import { AuthProvider, useAuth, RequirePermission } from './context/AuthContext'
import { Toaster } from "@/components/ui/sonner"
import { ThemeProvider } from "next-themes"
import { Spinner } from "@/components/ui/spinner"

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

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route element={
        <ProtectedRoute>
          <DashboardLayout />
        </ProtectedRoute>
      }>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/projects" element={<ProjectsPage />} />
        <Route path="/projects/:id" element={<ProjectDetails />} />
        <Route path="/projects/:projectId/scans/:scanId" element={<ScanDetails />} />
        <Route path="/teams" element={<TeamsPage />} />
        <Route path="/profile" element={<ProfilePage />} />
        <Route path="/users" element={
          <RequirePermission permission="user:manage">
            <UsersPage />
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
