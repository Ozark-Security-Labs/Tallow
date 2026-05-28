import type { Role } from '../api/generated';

export function hasRole(roles: Role[] | undefined, role: Role) {
  return roles?.includes(role) ?? false;
}

export function canManageSettings(capabilities: string[] | undefined) {
  return capabilities?.includes('settings:mutate') ?? false;
}
