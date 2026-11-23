"use client";

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Webhook, Search, ShieldAlert, FileCode } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input, NativeSelect } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/menus";
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
  HttpStatusBadge,
} from "@/components/status-badges";
import { ScanSelector } from "@/components/scan-selector";
import { FindingsTableView } from "@/components/findings-view";
import { useActiveScan } from "@/components/providers";
import { api, errorMessage } from "@/lib/api";
import {
  API_ENDPOINT_CATEGORIES,
  type ApiEndpoint,
  type ApiEndpointCategory,
} from "@/lib/types";
import { formatDate, humanize } from "@/lib/utils";

export default function ApiExplorerPage() {
  const { selectedScanId } = useActiveScan();
  const [categoryFilter, setCategoryFilter] = React.useState<ApiEndpointCategory | "">("");
  const [search, setSearch] = React.useState("");
  const [selectedEndpoint, setSelectedEndpoint] = React.useState<ApiEndpoint | null>(null);

  const endpointsQuery = useQuery({
    queryKey: ["scans", selectedScanId, "endpoints", categoryFilter],
    queryFn: () =>
      api.listEndpoints(selectedScanId, {
        category: categoryFilter || undefined,
      }),
    enabled: !!selectedScanId,
  });

  const findingsQuery = useQuery({
    queryKey: ["findings", selectedScanId, "api_security"],
    queryFn: () => api.listFindings(selectedScanId, { category: "api_security" }),
    enabled: !!selectedScanId,
  });

  const endpoints = React.useMemo(() => {
    const list = endpointsQuery.data?.items ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return list;
    return list.filter((ep) =>
      `${ep.path_template} ${ep.url} ${ep.methods.join(" ")} ${ep.category}`.toLowerCase().includes(q),
    );
  }, [endpointsQuery.data, search]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">API Surface Explorer</h1>
          <p className="text-xs text-muted-foreground">
            REST, GraphQL, BaaS, and webhook endpoints extracted from client bundles and traffic, with authentication
            and CORS posture analysis.
          </p>
        </div>
        <ScanSelector />
      </div>

      {endpointsQuery.isError && (
        <ErrorBanner
          message={errorMessage(endpointsQuery.error)}
          onRetry={() => void endpointsQuery.refetch()}
        />
      )}

      {!selectedScanId ? (
        <EmptyState
          icon={<Webhook className="h-5 w-5" />}
          title="No scan selected"
          description="Select a scan to inspect discovered API endpoints and API security findings."
        />
      ) : (
        <Tabs defaultValue="endpoints">
          <TabsList>
            <TabsTrigger value="endpoints">
              <Webhook className="h-3.5 w-3.5" />
              Discovered API Endpoints ({endpointsQuery.data?.total ?? 0})
            </TabsTrigger>
            <TabsTrigger value="findings">
              <ShieldAlert className="h-3.5 w-3.5" />
              API Security Findings ({findingsQuery.data?.total ?? 0})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="endpoints" className="space-y-4">
            <Card>
              <CardContent className="flex flex-wrap items-center gap-3 p-3">
                <div className="relative min-w-[220px] flex-1">
                  <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Filter by endpoint path, method, or URL…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="pl-8"
                  />
                </div>
                <NativeSelect
                  aria-label="Filter by endpoint category"
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value as ApiEndpointCategory | "")}
                  className="w-48"
                >
                  <option value="">All API categories</option>
                  {API_ENDPOINT_CATEGORIES.map((c) => (
                    <option key={c} value={c}>
                      {humanize(c)}
                    </option>
                  ))}
                </NativeSelect>
              </CardContent>
            </Card>

            {endpoints.length === 0 ? (
              <EmptyState
                icon={<Webhook className="h-5 w-5" />}
                title="No API endpoints matched"
                description="Try clearing the category or search filter."
              />
            ) : (
              <Card>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Methods</TableHead>
                      <TableHead>Endpoint Path</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>HTTP Status</TableHead>
                      <TableHead>Auth Observation</TableHead>
                      <TableHead>CORS Posture</TableHead>
                      <TableHead>Discovery Sources</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {endpoints.map((ep) => (
                      <TableRow
                        key={ep.id}
                        onClick={() => setSelectedEndpoint(ep)}
                        className="cursor-pointer"
                      >
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {ep.methods.map((m) => (
                              <Badge key={m} variant="outline" className="font-mono text-[10px]">
                                {m}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="font-mono text-xs font-semibold text-cyan-300">
                            {ep.path_template}
                          </div>
                          <div className="max-w-xs truncate font-mono text-[11px] text-muted-foreground">
                            {ep.url}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">{humanize(ep.category)}</Badge>
                        </TableCell>
                        <TableCell>
                          <HttpStatusBadge code={ep.status_code} />
                        </TableCell>
                        <TableCell>
                          <AuthObservationBadge observation={ep.auth_observation} />
                        </TableCell>
                        <TableCell>
                          {ep.cors.reflects_origin && ep.cors.allow_credentials ? (
                            <Badge variant="danger">Reflects origin + credentials</Badge>
                          ) : ep.cors.allow_origin === "*" ? (
                            <Badge variant="warning">Wildcard (*)</Badge>
                          ) : ep.cors.allow_origin ? (
                            <Badge variant="outline" className="font-mono text-[10px]">
                              {ep.cors.allow_origin}
                            </Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground">Restricted</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {ep.sources.map((s) => (
                              <Badge key={s} variant="outline" className="font-mono text-[10px]">
                                {s}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="findings">
            <FindingsTableView
              findings={findingsQuery.data?.items ?? []}
              allowedCategories={["api_security"]}
              emptyTitle="No API security findings"
              emptyDescription="No permissive CORS, unauthenticated data exposure, or unsafe API patterns were flagged."
            />
          </TabsContent>
        </Tabs>
      )}

      {/* API Endpoint Detail Sheet */}
      <Sheet open={!!selectedEndpoint} onOpenChange={(o) => !o && setSelectedEndpoint(null)}>
        <SheetContent side="right" className="sm:max-w-2xl">
          {selectedEndpoint && (
            <>
              <SheetHeader>
                <div className="flex flex-wrap items-center gap-2">
                  {selectedEndpoint.methods.map((m) => (
                    <Badge key={m} variant="default" className="font-mono">
                      {m}
                    </Badge>
                  ))}
                  <HttpStatusBadge code={selectedEndpoint.status_code} />
                  <AuthObservationBadge observation={selectedEndpoint.auth_observation} />
                  <Badge variant="secondary">{humanize(selectedEndpoint.category)}</Badge>
                </div>
                <SheetTitle className="mt-1 font-mono text-base text-cyan-300">
                  {selectedEndpoint.path_template}
                </SheetTitle>
                <SheetDescription className="break-all font-mono text-xs">
                  {selectedEndpoint.url}
                </SheetDescription>
              </SheetHeader>

              <SheetBody className="space-y-5 text-sm">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                  <div className="rounded-md border bg-zinc-900/50 p-2.5">
                    <div className="text-[11px] text-muted-foreground">Content-Type</div>
                    <div className="mt-0.5 font-mono text-xs text-zinc-200">
                      {selectedEndpoint.content_type || "—"}
                    </div>
                  </div>
                  <div className="rounded-md border bg-zinc-900/50 p-2.5">
                    <div className="text-[11px] text-muted-foreground">Safe Probe Tested</div>
                    <div className="mt-0.5 text-xs text-zinc-200">
                      {selectedEndpoint.tested ? "Yes (read-only)" : "Not probed"}
                    </div>
                  </div>
                  <div className="rounded-md border bg-zinc-900/50 p-2.5">
                    <div className="text-[11px] text-muted-foreground">Discovered</div>
                    <div className="mt-0.5 text-xs text-zinc-200">
                      {formatDate(selectedEndpoint.created_at)}
                    </div>
                  </div>
                </div>

                {selectedEndpoint.test_note && (
                  <div className="rounded-md border bg-zinc-900/40 p-3 text-xs text-zinc-300">
                    <strong>Test Note:</strong> {selectedEndpoint.test_note}
                  </div>
                )}

                {/* CORS Details */}
                <div className="rounded-md border bg-zinc-950/70 p-3 text-xs">
                  <h4 className="font-semibold uppercase tracking-wider text-muted-foreground">
                    CORS Policy Observation
                  </h4>
                  <div className="mt-2 grid grid-cols-3 gap-2 font-mono">
                    <div>
                      <span className="text-muted-foreground">Allow-Origin:</span>{" "}
                      <span className="text-zinc-200">{selectedEndpoint.cors.allow_origin ?? "none"}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Allow-Credentials:</span>{" "}
                      <span className="text-zinc-200">
                        {String(selectedEndpoint.cors.allow_credentials)}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Reflects Origin:</span>{" "}
                      <span className="text-zinc-200">
                        {String(selectedEndpoint.cors.reflects_origin)}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Evidence */}
                <div className="space-y-2">
                  <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    <FileCode className="h-3.5 w-3.5 text-cyan-400" />
                    Extraction & Response Evidence ({selectedEndpoint.evidence.length})
                  </h4>
                  {selectedEndpoint.evidence.map((ev, idx) => (
                    <div key={idx} className="rounded-md border bg-zinc-950/80 p-3 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300">
                          {ev.type}
                        </span>
                        {ev.location && (
                          <span className="font-mono text-[11px] text-muted-foreground">{ev.location}</span>
                        )}
                      </div>
                      <p className="mt-1.5 text-zinc-200">{ev.detail}</p>
                      {ev.snippet && (
                        <pre className="mt-2 max-h-48 overflow-auto rounded border border-zinc-800 bg-black/70 p-2 font-mono text-[11px] text-zinc-300">
                          <code>{ev.snippet}</code>
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              </SheetBody>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
