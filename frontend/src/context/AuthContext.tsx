import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, getToken, setToken, setUnauthorizedHandler } from "../lib/api";
import type { User } from "../lib/types";

type AuthContextValue = {
  user: User | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<User>;
  signUp: (email: string, name: string, password: string) => Promise<User>;
  signOut: () => Promise<void>;
  refreshUser: () => Promise<User | null>;
  setUser: (user: User) => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUserState] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUserState(null);
    });
    let cancelled = false;
    if (!getToken()) {
      setLoading(false);
    } else {
      api.auth
        .me()
        .then((profile) => {
          if (!cancelled) setUserState(profile);
        })
        .catch(() => {
          if (!cancelled) {
            setToken(null);
            setUserState(null);
          }
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }
    return () => {
      cancelled = true;
      setUnauthorizedHandler(null);
    };
  }, []);

  const signIn = useCallback(async (email: string, password: string) => {
    const response = await api.auth.login(email, password);
    setToken(response.access_token);
    setUserState(response.user);
    return response.user;
  }, []);

  const signUp = useCallback(async (email: string, name: string, password: string) => {
    const response = await api.auth.register(email, name, password);
    setToken(response.access_token);
    setUserState(response.user);
    return response.user;
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.auth.logout();
    } catch {
      // Stateless JWT: local token removal is sufficient even if audit logging fails.
    }
    setToken(null);
    setUserState(null);
  }, []);

  const refreshUser = useCallback(async () => {
    if (!getToken()) return null;
    const profile = await api.auth.me();
    setUserState(profile);
    return profile;
  }, []);

  const setUser = useCallback((profile: User) => setUserState(profile), []);

  const value = useMemo(
    () => ({ user, loading, signIn, signUp, signOut, refreshUser, setUser }),
    [user, loading, signIn, signUp, signOut, refreshUser, setUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider.");
  return context;
}
