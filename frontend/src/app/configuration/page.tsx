"use client";

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Settings2, Cpu, FileCode } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/menus";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScanSelector } from "@/components/scan-selector";
import { FindingsTableView } from "@/components/findings-view";
import { EmptyState, ErrorBanner } from "@/components/status-badges";
import { useActiveScan } from "@/components/providers";
import { api, errorMessage } from "@/lib/api";
import { CONFIG_CATEGORIES } from "@/lib/constants";
import { formatBytes, formatPercent, shortHash } from "@/lib/utils";

export default function ConfigurationAuditPage() {
  const { selectedScanId } = useActiveScan();

  const findingsQuery = useQuery({
    queryKey: ["findings", selectedScanId, "configuration"],
    queryFn: () => api.listFindings(selectedScanId),
    enabled: !!selectedScanId,
  });

  const techQuery = useQuery({
    queryKey: ["scans", selectedScanId, "technologies"],
    queryFn: () => api.getTechnologies(selectedScanId),
    enabled: !!selectedScanId,
  });

  const assetsQuery = useQuery({
    queryKey: ["scans", selectedScanId, "assets"],
    queryFn: () => api.listAssets(selectedScanId),
    enabled: !!selectedScanId,
  });

  const technologies = techQuery.data?.items ?? [];
  const assets = assetsQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">Configuration, Secrets & Headers Audit</h1>
          <p className="text-xs text-muted-foreground">
            Exposed client secrets, missing HTTP security headers, information disclosure, BaaS database policies,
            fingerprinted stack, and source maps.
          </p>
        </div>
        <ScanSelector />
      </div>

      {findingsQuery.isError && (
        <ErrorBanner
          message={errorMessage(findingsQuery.error)}
          onRetry={() => void findingsQuery.refetch()}
        />
      )}

      {!selectedScanId ? (
        <EmptyState
          icon={<Settings2 className="h-5 w-5" />}
          title="No scan selected"
          description="Select a scan to inspect configuration findings, fingerprinted technologies, and client assets."
        />
      ) : (
        <Tabs defaultValue="findings">
          <TabsList>
            <TabsTrigger value="findings">
              <Settings2 className="h-3.5 w-3.5" />
              Configuration & Secret Findings
            </TabsTrigger>
            <TabsTrigger value="technologies">
              <Cpu className="h-3.5 w-3.5" />
              Fingerprinted Stack ({technologies.length})
            </TabsTrigger>
            <TabsTrigger value="assets">
              <FileCode className="h-3.5 w-3.5" />
              Analyzed Bundles & Source Maps ({assets.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="findings">
            <FindingsTableView
              findings={findingsQuery.data?.items ?? []}
              allowedCategories={CONFIG_CATEGORIES}
              emptyTitle="No configuration or secret exposure findings"
              emptyDescription="No exposed environment variables, hardcoded bundle secrets, or security header issues matched your filters."
            />
          </TabsContent>

          <TabsContent value="technologies">
            {technologies.length === 0 ? (
              <EmptyState
                icon={<Cpu className="h-5 w-5" />}
                title="No stack technologies fingerprinted"
                description="Run a scan with crawling enabled to fingerprint frameworks, BaaS providers, and platforms."
              />
            ) : (
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {technologies.map((tech) => (
                  <Card key={tech.id}>
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <CardTitle>{tech.name}</CardTitle>
                        <div className="flex items-center gap-1.5">
                          <Badge variant="outline" className="uppercase">
                            {tech.kind}
                          </Badge>
                          <Badge variant="default" className="font-mono">
                            {formatPercent(tech.confidence)}
                          </Badge>
                        </div>
                      </div>
                      <CardDescription>Detected via {tech.evidence.length} passive signal(s)</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-1.5 text-xs">
                      {tech.evidence.map((ev, i) => (
                        <div key={i} className="rounded border bg-zinc-950/70 px-2.5 py-1.5">
                          <div className="flex items-center justify-between font-mono text-[11px] text-cyan-300">
                            <span>{ev.signal}</span>
                            <span>weight {ev.weight}</span>
                          </div>
                          <p className="mt-0.5 text-muted-foreground">{ev.detail}</p>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="assets">
            {assets.length === 0 ? (
              <EmptyState
                icon={<FileCode className="h-5 w-5" />}
                title="No static assets recorded"
                description="JavaScript bundles and asset metadata appear here after crawling."
              />
            ) : (
              <Card>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Asset URL</TableHead>
                      <TableHead>Kind</TableHead>
                      <TableHead>Size</TableHead>
                      <TableHead>SHA-256</TableHead>
                      <TableHead>Source Map Posture</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {assets.map((asset) => (
                      <TableRow key={asset.id}>
                        <TableCell className="max-w-md break-all font-mono text-xs text-zinc-200">
                          {asset.url}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="uppercase">
                            {asset.kind}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-zinc-300">
                          {formatBytes(asset.size_bytes)}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {shortHash(asset.sha256, 16)}
                        </TableCell>
                        <TableCell>
                          {asset.source_map_exposed ? (
                            <Badge variant="danger">Exposed ({asset.source_map_url ?? ".map"})</Badge>
                          ) : asset.source_map_url ? (
                            <Badge variant="warning">Referenced ({asset.source_map_url})</Badge>
                          ) : (
                            <Badge variant="success">Not exposed</Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Card>
            )}
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}
