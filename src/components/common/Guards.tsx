import React from 'react';
import { useAuth } from '../../context/AuthContext';
import { ConceptualRole, FeatureEntitlements, UserRole } from '../../types';

interface RoleGuardProps {
  roles: (ConceptualRole | UserRole | string)[];
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export const RoleGuard: React.FC<RoleGuardProps> = ({ roles, children, fallback = null }) => {
  const { role, conceptualRole } = useAuth();
  const isAuthorized = roles.some(
    r => r === role || r === conceptualRole ||
    ((r === 'SUPER_ADMIN' || r === 'SYS_ADMIN') && (role === 'SYS_ADMIN' || role === 'SUPER_ADMIN'))
  );

  if (!isAuthorized) {
    return <>{fallback}</>;
  }
  return <>{children}</>;
};

interface PermissionGuardProps {
  permission: string;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export const PermissionGuard: React.FC<PermissionGuardProps> = ({ permission, children, fallback = null }) => {
  const { hasPermission } = useAuth();
  if (!hasPermission(permission)) {
    return <>{fallback}</>;
  }
  return <>{children}</>;
};

interface EntitlementGuardProps {
  entitlement: keyof FeatureEntitlements;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export const EntitlementGuard: React.FC<EntitlementGuardProps> = ({ entitlement, children, fallback = null }) => {
  const { hasEntitlement } = useAuth();
  if (!hasEntitlement(entitlement)) {
    return <>{fallback}</>;
  }
  return <>{children}</>;
};
