"use client";

import * as React from "react";
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import { usePathname, useRouter } from "next/navigation";
import { api, setCsrfToken } from "@/lib/api";
import type { Operator, Scan } from "@/lib/types";

interface AuthContextValue {
  operator: Operator | null;
  isLoading: boolean;
  refreshAuth: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = React.createContext<AuthContextValue>({
  operator: null,
  isLoading: true,
  refreshAuth: async () => {},
  logout: async () => {},
});

export function useAuth() {
  return React.useContext(AuthContext);
}

interface ScanContextValue {
  selectedScanId: string;
  setSelectedScanId: (id: string) => void;
  scans: Scan[];
  selectedScan: Scan | null;
  isLoadingScans: boolean;
}

const ScanContext = React.createContext<ScanContextValue>({
  selectedScanId: "",
  setSelectedScanId: () => {},
  scans: [],
  selectedScan: null,
  isLoadingScans: false,
});

export function useActiveScan() {
  return React.useContext(ScanContext);
}

const STORAGE_KEY = "vibescan_selected_scan_id";

function AuthAndScanProvider({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const queryClient = useQueryClient();
  const isLoginPage = pathname?.startsWith("/login");

  const authQuery = useQuery({
    queryKey: ["auth", "me"],
    queryFn: async () => {
      const session = await api.me();
      setCsrfToken(session.csrf_token);
      return session;
    },
    retry: false,
    staleTime: 60_000,
    enabled: !isLoginPage,
  });

  React.useEffect(() => {
    if (!isLoginPage && authQuery.isError) {
      const next = pathname ? `?next=${encodeURIComponent(pathname)}` : "";
      router.replace(`/login${next}`);
    }
  }, [isLoginPage, authQuery.isError, pathname, router]);

  const scansQuery = useQuery({
    queryKey: ["scans", "list-global"],
    queryFn: () => api.listScans({ limit: 100 }),
    enabled: !isLoginPage && !!authQuery.data?.operator,
    staleTime: 10_000,
  });

  const [selectedScanId, setSelectedScanIdState] = React.useState<string>("");

  React.useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const fromUrl = params.get("scan");
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (fromUrl) {
      setSelectedScanIdState(fromUrl);
      window.localStorage.setItem(STORAGE_KEY, fromUrl);
    } else if (saved) {
      setSelectedScanIdState(saved);
    }
  }, [pathname]);

  const scans = React.useMemo(() => scansQuery.data?.items ?? [], [scansQuery.data]);

  React.useEffect(() => {
    if (!scans.length) return;
    if (!selectedScanId || !scans.some((s) => s.id === selectedScanId)) {
      const first = scans[0].id;
      setSelectedScanIdState(first);
      if (typeof window !== "undefined") {
        window.localStorage.setItem(STORAGE_KEY, first);
      }
    }
  }, [scans, selectedScanId]);

  const setSelectedScanId = React.useCallback((id: string) => {
    setSelectedScanIdState(id);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(STORAGE_KEY, id);
    }
  }, []);

  const selectedScan = React.useMemo(
    () => scans.find((s) => s.id === selectedScanId) ?? scans[0] ?? null,
    [scans, selectedScanId],
  );

  const refreshAuth = React.useCallback(async () => {
    await queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
  }, [queryClient]);

  const logout = React.useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // ignore logout error
    }
    setCsrfToken(null);
    queryClient.clear();
    router.replace("/login");
  }, [queryClient, router]);

  return (
    <AuthContext.Provider
      value={{
        operator: authQuery.data?.operator ?? null,
        isLoading: !isLoginPage && authQuery.isLoading,
        refreshAuth,
        logout,
      }}
    >
      <ScanContext.Provider
        value={{
          selectedScanId: selectedScan?.id ?? selectedScanId,
          setSelectedScanId,
          scans,
          selectedScan,
          isLoadingScans: scansQuery.isLoading,
        }}
      >
        {children}
      </ScanContext.Provider>
    </AuthContext.Provider>
  );
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = React.useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            refetchOnWindowFocus: false,
            retry: 1,
          },
        },
      }),
  );

  return (
    <QueryClientProvider client={queryClient}>
      <AuthAndScanProvider>{children}</AuthAndScanProvider>
    </QueryClientProvider>
  );
}
