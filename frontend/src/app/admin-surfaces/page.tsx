"use client";

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, Search, ArrowRight, FileCode, Compass } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input, NativeSelect } from "@/components/ui/input";
import { Switch } from "@/components/ui/form-controls";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/dialog";
import {
  AuthObservationBadge,
  EmptyState,
  ErrorBanner,
  FindingStatusBadge,
  HttpStatusBadge,
  SeverityBadge,
} from "@/components/status-badges";
import { ScanSelector } from "@/components/scan-selector";
import { FindingSheet } from "@/components/finding-sheet";
import { useActiveScan } from "@/components/providers";
import { api, errorMessage } from "@/lib/api";
import {
  ADMIN_CATEGORY_LABEL,
  AUTH_OBSERVATION_LABEL,
  SEVERITY_ORDER,
} from "@/lib/constants";
import {
  ADMIN_CATEGORIES,
  AUTH_OBSERVATIONS,
  RISK_LEVELS,
  type AdminCategory,
  type AuthObservation,
  type Finding,
  type RiskLevel,
  type Route,
} from "@/lib/types";
import { formatDate, formatPercent } from "@/lib/utils";

export default function AdminSurfacesPage() {
  const { selectedScanId } = useActiveScan();
  const [adminOnly, setAdminOnly] = React.useState(true);
  const [categoryFilter, setCategoryFilter] = React.useState<AdminCategory | "">("");
  const [riskFilter, setRiskFilter] = React.useState<RiskLevel | "">("");
  const [authFilter, setAuthFilter] = React.useState<AuthObservation | "">("");
  const [search, setSearch] = React.useState("");
  const [selectedRoute, setSelectedRoute] = React.useState<Route | null>(null);
  const [selectedFinding, setSelectedFinding] = React.useState<Finding | null>(null);

  const routesQuery = useQuery({
    queryKey: ["scans", selectedScanId, "routes", { adminOnly, categoryFilter }],
    queryFn: () =>
      api.listRoutes(selectedScanId, {
        admin_only: adminOnly,
        category: categoryFilter || undefined,
      }),
    enabled: !!selectedScanId,
  });

  const findingsQuery = useQuery({
    queryKey: ["findings", selectedScanId, "all-for-routes"],
    queryFn: () => api.listFindings(selectedScanId),
    enabled: !!selectedScanId,
  });

  const filteredRoutes = React.useMemo(() => {
    const items = routesQuery.data?.items ?? [];
    const q = search.trim().toLowerCase();
    return items
      .filter((r) => {
        if (riskFilter && r.risk_level !== riskFilter) return false;
        if (authFilter && r.auth_observation !== authFilter) return false;
        if (q) {
          const hay = `${r.path} ${r.url} ${r.title ?? ""} ${r.evidence.map((e) => e.detail).join(" ")}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      })
      .sort((a, b) => SEVERITY_ORDER[a.risk_level] - SEVERITY_ORDER[b.risk_level]);
  }, [routesQuery.data, riskFilter, authFilter, search]);

  const relatedFindings = React.useMemo(() => {
    if (!selectedRoute) return [];
    const all = findingsQuery.data?.items ?? [];
    return all.filter(
      (f) =>
        f.affected === selectedRoute.url ||
        f.affected.endsWith(selectedRoute.path) ||
        (selectedRoute.path !== "/" && f.affected.includes(selectedRoute.path)),
    );
  }, [selectedRoute, findingsQuery.data]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">Admin Surface Explorer</h1>
          <p className="text-xs text-muted-foreground">
            Inspect discovered administrative routes, backoffice interfaces, authentication barriers, and bundle route
            leaks.
          </p>
        </div>
        <ScanSelector />
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-3">
          <div className="relative min-w-[220px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search route path, URL, title, or bundle evidence…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8"
            />
          </div>

          <NativeSelect
            aria-label="Admin category"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value as AdminCategory | "")}
            className="w-48"
          >
            <option value="">All admin categories</option>
            {ADMIN_CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {ADMIN_CATEGORY_LABEL[c]}
              </option>
            ))}
          </NativeSelect>

          <NativeSelect
            aria-label="Auth observation"
            value={authFilter}
            onChange={(e) => setAuthFilter(e.target.value as AuthObservation | "")}
            className="w-44"
          >
            <option value="">All auth observations</option>
            {AUTH_OBSERVATIONS.map((a) => (
              <option key={a} value={a}>
                {AUTH_OBSERVATION_LABEL[a]}
              </option>
            ))}
          </NativeSelect>

          <NativeSelect
            aria-label="Risk level"
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value as RiskLevel | "")}
            className="w-36"
          >
            <option value="">All risk levels</option>
            {RISK_LEVELS.map((r) => (
              <option key={r} value={r}>
                {r.toUpperCase()}
              </option>
            ))}
          </NativeSelect>

          <label className="flex items-center gap-2 rounded-md border bg-zinc-900/60 px-3 py-1.5 text-xs">
            <span>Admin surfaces only</span>
            <Switch checked={adminOnly} onCheckedChange={setAdminOnly} />
          </label>
        </CardContent>
      </Card>

      {routesQuery.isError && (
        <ErrorBanner
          message={errorMessage(routesQuery.error)}
          onRetry={() => void routesQuery.refetch()}
        />
      )}

      {!selectedScanId ? (
        <EmptyState
          icon={<ShieldAlert className="h-5 w-5" />}
          title="No scan selected"
          description="Select or run a security scan to explore discovered administrative surfaces."
        />
      ) : filteredRoutes.length === 0 && !routesQuery.isLoading ? (
        <EmptyState
          icon={<ShieldAlert className="h-5 w-5" />}
          title="No administrative routes matched"
          description="Toggle off 'Admin surfaces only' to inspect all discovered application routes."
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Route</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>HTTP status</TableHead>
                <TableHead>Authentication observation</TableHead>
                <TableHead>Risk level</TableHead>
                <TableHead>Evidence</TableHead>
                <TableHead>Scan timestamp</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredRoutes.map((route) => (
                <TableRow
                  key={route.id}
                  onClick={() => setSelectedRoute(route)}
                  className="cursor-pointer"
                >
                  <TableCell>
                    <div className="font-mono text-xs font-semibold text-cyan-300">{route.path}</div>
                    <div className="max-w-xs truncate text-[11px] text-muted-foreground">
                      {route.title ? `${route.title} · ` : ""}
                      {route.url}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary">
                      {ADMIN_CATEGORY_LABEL[route.admin_category] ?? route.admin_category}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <HttpStatusBadge code={route.status_code} />
                  </TableCell>
                  <TableCell>
                    <AuthObservationBadge observation={route.auth_observation} />
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={route.risk_level} />
                  </TableCell>
                  <TableCell className="max-w-xs">
                    {route.evidence[0] ? (
                      <div className="truncate text-xs text-zinc-300" title={route.evidence[0].detail}>
                        <span className="mr-1.5 rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] text-cyan-300">
                          {route.evidence[0].type}
                        </span>
                        {route.evidence[0].detail}
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                    {formatDate(route.created_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Route Detail Sheet */}
      <Sheet open={!!selectedRoute} onOpenChange={(o) => !o && setSelectedRoute(null)}>
        <SheetContent side="right" className="sm:max-w-2xl">
          {selectedRoute && (
            <>
              <SheetHeader>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={selectedRoute.risk_level} />
                  <AuthObservationBadge observation={selectedRoute.auth_observation} />
                  <HttpStatusBadge code={selectedRoute.status_code} />
                  <Badge variant="secondary">
                    {ADMIN_CATEGORY_LABEL[selectedRoute.admin_category]}
                  </Badge>
                </div>
                <SheetTitle className="mt-1 font-mono text-base text-cyan-300">
                  {selectedRoute.path}
                </SheetTitle>
                <SheetDescription className="break-all font-mono text-xs">
                  {selectedRoute.url}
                </SheetDescription>
              </SheetHeader>

              <SheetBody className="space-y-5 text-sm">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div className="rounded-md border bg-zinc-900/50 p-2.5">
                    <div className="text-[11px] text-muted-foreground">Page Title</div>
                    <div className="mt-0.5 truncate text-xs font-medium text-zinc-200">
                      {selectedRoute.title || "—"}
                    </div>
                  </div>
                  <div className="rounded-md border bg-zinc-900/50 p-2.5">
                    <div className="text-[11px] text-muted-foreground">Content-Type</div>
                    <div className="mt-0.5 truncate font-mono text-xs text-zinc-200">
                      {selectedRoute.content_type || "—"}
                    </div>
                  </div>
                  <div className="rounded-md border bg-zinc-900/50 p-2.5">
                    <div className="text-[11px] text-muted-foreground">Classification Confidence</div>
                    <div className="mt-0.5 font-mono text-xs font-semibold text-cyan-300">
                      {formatPercent(selectedRoute.confidence)}
                    </div>
                  </div>
                  <div className="rounded-md border bg-zinc-900/50 p-2.5">
                    <div className="text-[11px] text-muted-foreground">Observed At</div>
                    <div className="mt-0.5 text-xs text-zinc-200">
                      {formatDate(selectedRoute.created_at)}
                    </div>
                  </div>
                </div>

                {/* Discovery methods */}
                <div>
                  <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    <Compass className="h-3.5 w-3.5 text-cyan-400" />
                    Discovery Methods
                  </h4>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {selectedRoute.discovery_methods.map((m) => (
                      <Badge key={m} variant="outline" className="font-mono text-xs text-zinc-200">
                        {m}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Redirect Chain */}
                <div>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    HTTP Redirect Chain ({selectedRoute.redirect_chain.length})
                  </h4>
                  {selectedRoute.redirect_chain.length === 0 ? (
                    <p className="mt-1 text-xs text-muted-foreground">
                      Direct response (no intermediate HTTP redirects observed).
                    </p>
                  ) : (
                    <div className="mt-2 space-y-1.5">
                      {selectedRoute.redirect_chain.map((hop, i) => (
                        <div
                          key={i}
                          className="flex flex-wrap items-center gap-2 rounded border bg-zinc-950/80 px-2.5 py-1.5 font-mono text-xs"
                        >
                          <HttpStatusBadge code={hop.status} />
                          <span className="break-all text-zinc-300">{hop.url}</span>
                          {hop.location && (
                            <>
                              <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" />
                              <span className="break-all text-cyan-300">{hop.location}</span>
                            </>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Evidence */}
                <div className="space-y-2">
                  <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    <FileCode className="h-3.5 w-3.5 text-cyan-400" />
                    Discovery & Classification Evidence ({selectedRoute.evidence.length})
                  </h4>
                  {selectedRoute.evidence.map((ev, i) => (
                    <div key={i} className="rounded-md border bg-zinc-950/80 p-3 text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300">
                          {ev.type}
                        </span>
                        {ev.location && (
                          <span className="font-mono text-[11px] text-muted-foreground">{ev.location}</span>
                        )}
                      </div>
                      <p className="mt-1.5 text-zinc-200">{ev.detail}</p>
                      {ev.snippet && (
                        <pre className="mt-2 max-h-44 overflow-auto rounded border border-zinc-800 bg-black/70 p-2 font-mono text-[11px] text-zinc-300">
                          <code>{ev.snippet}</code>
                        </pre>
                      )}
                    </div>
                  ))}
                </div>

                {/* Related Findings */}
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Related Security Findings ({relatedFindings.length})
                  </h4>
                  {relatedFindings.length === 0 ? (
                    <p className="text-xs text-muted-foreground">
                      No direct security findings linked to this route path.
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {relatedFindings.map((f) => (
                        <button
                          key={f.id}
                          type="button"
                          onClick={() => setSelectedFinding(f)}
                          className="flex w-full items-center justify-between gap-2 rounded-md border bg-zinc-900/60 p-2.5 text-left text-xs hover:border-cyan-500/40"
                        >
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-cyan-300">{f.finding_key}</span>
                              <SeverityBadge severity={f.severity} />
                              <FindingStatusBadge status={f.status} />
                            </div>
                            <p className="mt-1 font-medium text-zinc-100">{f.title}</p>
                          </div>
                          <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </SheetBody>
            </>
          )}
        </SheetContent>
      </Sheet>

      <FindingSheet
        finding={selectedFinding}
        open={!!selectedFinding}
        onOpenChange={(o) => !o && setSelectedFinding(null)}
      />
    </div>
  );
}
