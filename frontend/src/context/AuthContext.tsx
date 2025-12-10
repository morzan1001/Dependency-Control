import React, { createContext, useContext, useState, useEffect } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { setLogoutCallback, getMe } from '@/lib/api';
import { jwtDecode } from 'jwt-decode';

interface DecodedToken {
  exp: number;
  iat: number;
  sub: string;
  permissions: string[];
  type: string;
}

interface AuthContextType {
  isAuthenticated: boolean;
  login: (accessToken: string, refreshToken: string) => void;
  logout: () => void;
  isLoading: boolean;
  permissions: string[];
  hasPermission: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [permissions, setPermissions] = useState<string[]>([]);
  const navigate = useNavigate();

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('refresh_token');
    setIsAuthenticated(false);
    setPermissions([]);
    navigate('/login');
  };

  const hasPermission = (permission: string) => {
    return permissions.includes('*') || permissions.includes(permission);
  };

  useEffect(() => {
    setLogoutCallback(logout);

    const initAuth = async () => {
        const token = localStorage.getItem('token');
        if (!token) {
            setIsAuthenticated(false);
            setIsLoading(false);
            return;
        }

        try {
            const decoded: DecodedToken = jwtDecode(token);
            setPermissions(decoded.permissions || []);
            await getMe();
            setIsAuthenticated(true);
        } catch (error) {
            console.error("Auth init failed", error);
            setIsAuthenticated(false);
        } finally {
            setIsLoading(false);
        }
    };

    initAuth();
  }, []);

  const login = (accessToken: string, refreshToken: string) => {
    localStorage.setItem('token', accessToken);
    localStorage.setItem('refresh_token', refreshToken);
    
    try {
        const decoded: DecodedToken = jwtDecode(accessToken);
        const perms = decoded.permissions || [];
        setPermissions(perms);
        
        // Check if this is a limited token for 2FA setup
        if (perms.length === 1 && perms[0] === 'auth:setup_2fa') {
            setIsAuthenticated(true);
            navigate('/setup-2fa');
            return;
        }
    } catch (e) {
        console.error("Failed to decode token on login", e);
    }

    setIsAuthenticated(true);
    navigate('/dashboard');
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout, isLoading, permissions, hasPermission }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    // Check if we are already on the login page to avoid loops, though the router should handle this.
    // Also check if we have a token in storage but state hasn't updated yet (initial load)
    if (!localStorage.getItem('token')) {
        return null; // Or a loading spinner, or Navigate to login
    }
  }

  return <>{children}</>;
}

export function RequirePermission({ children, permission }: { children: React.ReactNode, permission: string | string[] }) {
  const { hasPermission, isLoading } = useAuth();
  
  if (isLoading) {
      return null;
  }

  const hasAccess = Array.isArray(permission)
    ? permission.some(p => hasPermission(p))
    : hasPermission(permission);

  if (!hasAccess) {
      return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}
