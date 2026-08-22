import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { AuthUser, ConceptualRole, FeatureEntitlements, UserRole, AuthStatus } from '../types';
import { api } from '../services/api';

interface AuthContextType {
  user: AuthUser | null;
  authStatus: AuthStatus;
  role: UserRole;
  conceptualRole: ConceptualRole;
  activeViewRole: ConceptualRole;
  canPreviewRoles: boolean;
  permissions: string[];
  entitlements: FeatureEntitlements;
  isLoading: boolean;
  login: (username: string, password: string, deviceId?: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  switchRoleView: (newRole: string) => Promise<{ success: boolean; error?: string }>;
  switchRole: (newRole: string) => Promise<void>;
  refreshAuth: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
  hasEntitlement: (entitlement: keyof FeatureEntitlements) => boolean;
}

const DEFAULT_ENTITLEMENTS: FeatureEntitlements = {
  FILE_SCAN: true,
  ENDPOINT_COMPLIANCE: true,
  REPORTS: true,
  SCHEDULED_SCAN: true,
  CLOUD_COMPLIANCE: true
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatus>('loading');
  const [activeViewRole, setActiveViewRole] = useState<ConceptualRole>('USER');
  const hasInitialized = useRef(false);

  const resolveConceptualRole = (u: AuthUser): ConceptualRole => {
    if (u.conceptualRole) return u.conceptualRole;
    if (u.role === 'SYS_ADMIN' || u.role === 'SUPER_ADMIN') return 'SUPER_ADMIN';
    if (u.role === 'ORG_ADMIN') return 'ORG_ADMIN';
    return 'USER';
  };

  const refreshAuth = useCallback(async () => {
    try {
      const token = api.getAuthToken();
      if (!token) {
        setUser(null);
        setActiveViewRole('USER');
        setAuthStatus('unauthenticated');
        return;
      }

      const me = await api.getMe();
      if (me) {
        setUser(me);
        const naturalRole = resolveConceptualRole(me);

        // Saved preview role is only respected if user has preview privileges
        const savedViewRole = typeof window !== 'undefined' ? (sessionStorage.getItem('filesentinel_view_role') as ConceptualRole | null) : null;
        const canPreview = Boolean(
          naturalRole === 'SUPER_ADMIN' ||
          me.role === 'ORG_ADMIN' ||
          (typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production')
        );

        if (canPreview && savedViewRole && ['USER', 'ORG_ADMIN', 'SUPER_ADMIN'].includes(savedViewRole)) {
          setActiveViewRole(savedViewRole);
        } else {
          setActiveViewRole(naturalRole);
        }
        setAuthStatus('authenticated');
      } else {
        api.setAuthToken(null);
        setUser(null);
        setActiveViewRole('USER');
        setAuthStatus('unauthenticated');
      }
    } catch (err) {
      console.error('[AuthContext] Error verifying session:', err);
      api.setAuthToken(null);
      setUser(null);
      setActiveViewRole('USER');
      setAuthStatus('unauthenticated');
    }
  }, []);

  useEffect(() => {
    if (!hasInitialized.current) {
      hasInitialized.current = true;
      refreshAuth();
    }
  }, [refreshAuth]);

  const login = useCallback(async (username: string, password: string, deviceId?: string): Promise<{ success: boolean; error?: string }> => {
    setAuthStatus('loading');
    try {
      const res = await api.login(username, password, deviceId);
      if (res.token) {
        // Clear any previous view override on fresh login
        if (typeof window !== 'undefined') {
          sessionStorage.removeItem('filesentinel_view_role');
        }

        const me = await api.getMe();
        if (me) {
          setUser(me);
          const naturalRole = resolveConceptualRole(me);
          setActiveViewRole(naturalRole);
          setAuthStatus('authenticated');
          return { success: true };
        }
      }
      setUser(null);
      setAuthStatus('unauthenticated');
      return { success: false, error: 'Authentication succeeded but failed to load user profile' };
    } catch (err: any) {
      setUser(null);
      setAuthStatus('unauthenticated');
      return { success: false, error: err.message || 'Login error' };
    }
  }, []);

  const logout = useCallback(async () => {
    setAuthStatus('loading');
    try {
      await api.logout();
    } catch (err) {
      console.warn('[AuthContext] Logout warning:', err);
    } finally {
      if (typeof window !== 'undefined') {
        sessionStorage.removeItem('filesentinel_view_role');
      }
      setUser(null);
      setActiveViewRole('USER');
      setAuthStatus('unauthenticated');
    }
  }, []);

  const role: UserRole = user?.role || 'USER';
  const conceptualRole: ConceptualRole = user ? resolveConceptualRole(user) : 'USER';
  
  // Administrators and dev mode have role preview permissions
  const canPreviewRoles: boolean = Boolean(
    conceptualRole === 'SUPER_ADMIN' ||
    role === 'ORG_ADMIN' ||
    (typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production')
  );

  const switchRoleView = useCallback(async (newRole: string): Promise<{ success: boolean; error?: string }> => {
    const validRoles: ConceptualRole[] = ['USER', 'ORG_ADMIN', 'SUPER_ADMIN'];
    let targetConceptual: ConceptualRole = 'USER';

    if (newRole === 'SUPER_ADMIN' || newRole === 'SYS_ADMIN') targetConceptual = 'SUPER_ADMIN';
    else if (newRole === 'ORG_ADMIN') targetConceptual = 'ORG_ADMIN';
    else targetConceptual = 'USER';

    if (!validRoles.includes(targetConceptual)) {
      return { success: false, error: `Invalid preview role: ${newRole}` };
    }

    if (!canPreviewRoles && conceptualRole !== targetConceptual) {
      return { success: false, error: 'Role-view preview is only permitted for Administrators or in Development Mode.' };
    }

    // Set UI preview role in React state and session storage
    setActiveViewRole(targetConceptual);
    if (typeof window !== 'undefined') {
      sessionStorage.setItem('filesentinel_view_role', targetConceptual);
    }

    // Inform backend for audit logging without mutating DB user role
    try {
      await api.switchRoleView(newRole);
    } catch (err) {
      console.warn('[AuthContext] Backend role view sync note:', err);
    }

    return { success: true };
  }, [canPreviewRoles, conceptualRole]);

  const switchRole = useCallback(async (newRole: string) => {
    const res = await switchRoleView(newRole);
    if (!res.success) {
      throw new Error(res.error || 'Failed to switch role view');
    }
  }, [switchRoleView]);

  const permissions: string[] = user?.permissions || [];
  const entitlements: FeatureEntitlements = user?.entitlements || DEFAULT_ENTITLEMENTS;

  const hasPermission = useCallback((permission: string): boolean => {
    if (conceptualRole === 'SUPER_ADMIN') return true;
    return permissions.includes(permission);
  }, [conceptualRole, permissions]);

  const hasEntitlement = useCallback((entitlement: keyof FeatureEntitlements): boolean => {
    return entitlements[entitlement] ?? true;
  }, [entitlements]);

  const isLoading = authStatus === 'loading';

  return (
    <AuthContext.Provider
      value={{
        user,
        authStatus,
        role,
        conceptualRole,
        activeViewRole,
        canPreviewRoles,
        permissions,
        entitlements,
        isLoading,
        login,
        logout,
        switchRoleView,
        switchRole,
        refreshAuth,
        hasPermission,
        hasEntitlement
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

