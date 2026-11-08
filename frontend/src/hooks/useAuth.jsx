import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import * as api from '../services/api.js';

/**
 * Auth state for the whole app.
 * - The backend owns the session (httpOnly cookie). Nothing secret is stored in JS.
 * - `status`: 'checking' | 'authenticated' | 'anonymous' | 'unavailable'
 *   ('unavailable' = backend auth not reachable/implemented; the UI says so).
 */
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [status, setStatus] = useState('checking');

  const refresh = useCallback(async () => {
    try {
      const res = await api.getCurrentUser();
      setUser(res.user || null);
      setStatus(res.user ? 'authenticated' : 'anonymous');
    } catch (err) {
      setUser(null);
      // 401 = backend works, user just isn't signed in.
      setStatus(err.status === 401 ? 'anonymous' : 'unavailable');
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const login = useCallback(async (credentials) => {
    const res = await api.login(credentials);
    if (!res.user) throw new Error('The server did not return an account. Login was not completed.');
    setUser(res.user);
    setStatus('authenticated');
    return res.user;
  }, []);

  const register = useCallback(async (data) => {
    const res = await api.register(data);
    // Some backends sign the user in on registration; others require login after.
    if (res.user) {
      setUser(res.user);
      setStatus('authenticated');
    }
    return res;
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
      setStatus('anonymous');
    }
  }, []);

  const value = useMemo(() => ({ user, status, login, register, logout, refresh }), [user, status, login, register, logout, refresh]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}
