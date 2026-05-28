import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { api, ApiError } from '../api/client';
import type { CurrentUser } from '../api/generated';

type AuthState = { user: CurrentUser | null; loading: boolean; error: string | null; refresh: () => Promise<void>; logout: () => Promise<void> };
const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const refresh = async () => {
    setLoading(true);
    try { setUser(await api.me()); setError(null); }
    catch (err) { setUser(null); setError(err instanceof ApiError && err.status === 401 ? null : 'Unable to load auth state'); }
    finally { setLoading(false); }
  };
  const logout = async () => { await api.logout(); setUser(null); };
  useEffect(() => { void refresh(); }, []);
  const value = useMemo(() => ({ user, loading, error, refresh, logout }), [user, loading, error]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}
